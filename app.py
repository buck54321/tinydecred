"""
Copyright (c) 2019, Brian Stafford
See LICENSE for details

A PyQt light wallet. 
"""
import os
import sys
from PyQt5 import QtGui, QtCore, QtWidgets
from tinydecred import config
from tinydecred.util import helpers
from tinydecred.pydecred import constants as DCR
from tinydecred.pydecred.dcrdata import DcrdataBlockchain
from tinydecred.wallet import Wallet
from tinydecred.ui import screens, ui, qutilities as Q

# The directory of the tinydecred package.
PACKAGEDIR = os.path.dirname(os.path.realpath(__file__))

# Some commonly used ui constants.
TINY = ui.TINY
SMALL = ui.SMALL
MEDIUM = ui.MEDIUM
LARGE = ui.LARGE

# A filename for the wallet.
WALLET_FILE_NAME = "wallet.db"

formatTraceback = helpers.formatTraceback

currentWallet = "current.wallet"

def tryExecute(f, *a, **k):
    """
    Execute the function, catching exceptions and logging as an error. Return 
    False to indicate an exception. 

    Args:
        f (func): The function.
        *a (mixed): Optional positional arguments
        **k (mixed): Optional keyword arguments.

    Returns:
        False on failure, the function's return value on success.
    """
    try:
        return f(*a, **k)
    except Exception as e:
        log.error("tryExecute %s failed: %s" % (f.__name__, formatTraceback(e)))
    return False

class TinySignals(object):
    """
    Implements the Signals API as defined in tinydecred.api. TinySignals is used 
    by the Wallet to broadcast notifications.
    """
    def __init__(self, balance=None, working=None, done=None):
        """
        Args:
            balance (func(Balance)): A function to receive balance updates.
                Updates are broadcast as object implementing the Balance API.
        """
        dummy = lambda *a, **k: None
        self.balance = balance if balance else dummy
        self.working = working if working else dummy
        self.done = done if done else dummy

class TinyDecred(QtCore.QObject, Q.ThreadUtilities):
    """
    TinyDecred is an PyQt application for interacting with the Decred
    blockchain. TinyDecred currently implements a UI for creating and 
    controlling a rudimentary, non-staking, Decred testnet light wallet.

    TinyDecred is a system tray application. 
    """
    qRawSignal = QtCore.pyqtSignal(tuple)
    homeSig = QtCore.pyqtSignal()
    def __init__(self, qApp):
        """
        Args: 
            An initialized QApplication.
        """
        super().__init__()
        self.qApp = qApp
        self.wallet = None
        # Some CSS-styled elements to be updated if dark mode is enabled/disabled.
        self.trackedCssItems = []
       	st = self.sysTray = QtWidgets.QSystemTrayIcon(QtGui.QIcon(DCR.FAVICON))
        self.contextMenu = ctxMenu = QtWidgets.QMenu()
        ctxMenu.addAction("minimize").triggered.connect(self.minimizeApp)
        ctxMenu.addAction("quit").triggered.connect(lambda *a: self.qApp.quit())
       	st.setContextMenu(ctxMenu)
        st.activated.connect(self.sysTrayActivated)

        # The signalRegistry maps a signal to any number of receivers. Signals 
        # are routed through a Qt Signal.
        self.signalRegistry = {}
        self.qRawSignal.connect(self.signal_)
        self.blockchainSignals = TinySignals(
            balance = self.balanceSync,
            working = lambda: self.emitSignal(ui.WORKING_SIGNAL),
            done = lambda: self.emitSignal(ui.DONE_SIGNAL),
        )

        self.loadSettings()

        # The initialized DcrdataBlockchain will not be connected, as that is a
        # blocking operation. Connect will be called in a QThread in `initDCR`.
        self.dcrdata = DcrdataBlockchain(os.path.join(self.netDirectory(), "dcr.db"), cfg.net, self.getNetSetting("dcrdata"), skipConnect=True)

        # appWindow is the main application window. The TinyDialog class has 
        # methods for organizing a stack of Screen widgets. 
        self.appWindow = screens.TinyDialog(self)

        self.homeScreen = screens.HomeScreen(self)
        self.homeSig.connect(self.home_)
        self.home = lambda: self.homeSig.emit()

        self.appWindow.stack(self.homeScreen)

        self.pwDialog = screens.PasswordDialog(self)

        self.waitingScreen = screens.WaitingScreen(self)

        self.sendScreen = screens.SendScreen(self)

        self.sysTray.show()
        self.appWindow.show()

        # If there is a wallet file, prompt for a password to open the wallet, 
        # otherwise show the initialization screen.
        if os.path.isfile(self.walletFilename()):
            def openw(path, pw):
                try:
                    w = Wallet.openFile(path, pw)
                    w.open(0, pw, self.dcrdata, self.blockchainSignals)
                    self.appWindow.pop(self.pwDialog)
                    return w
                except Exception as e:
                    log.warning("exception encountered while attempting to open wallet: %s" % formatTraceback(e))
                    self.appWindow.showError("incorrect password")
            def login(pw):
                if pw is None or pw == "":
                    self.appWindow.showError("you must enter a password to continue")
                else:
                    path = self.walletFilename()
                    self.waitThread(openw, self.finishOpen, path, pw)                  
            self.getPassword(login)
        else:
            initScreen = screens.InitializationScreen(self)
            initScreen.setFadeIn(True)
            self.appWindow.stack(initScreen)

        # Connect to dcrdata in a QThread.             
        self.makeThread(self.initDCR, self.setDCR)
    def waiting(self):
        """
        Stack the waiting screen.
        """
        self.appWindow.stack(self.waitingScreen)
    def waitThread(self, f, cb, *a, **k):
        """
        Wait thread shows a waiting screen while the provided function is run
        in a separate thread. 

        Args:
            f (func): A function to run in a separate thread.
            cb (func): A callback to receive the return values from `f`.
            *args: Positional arguments passed to f.
            **kwargs: Keyword arguments passed directly to f.
        """
        cb = cb if cb else lambda *a, **k: None
        self.waiting()
        def unwaiting(*cba, **cbk):
            self.appWindow.pop(self.waitingScreen)
            cb(*cba, **cbk)
        self.makeThread(tryExecute, unwaiting, f, *a, **k)
    def finishOpen(self, wallet):
        """
        Callback for the initial wallet load. If the load failed, probably
        because of a bad password, the provided wallet will be None.

        Args:
            wallet (Wallet): The newly opened Wallet instance. 
        """
        if wallet == None:
            return
        self.setWallet(wallet)
        self.home()
    def getPassword(self, f, *args, **kwargs):
        """
        Calls the provided function with a user-provided password string as its
        first argument. Any additional arguments provided to getPassword are 
        appended as-is to the password argument. 

        Args:
            f (func): A function that will receive the user's password
                and any other provided arguments.
            *args: Positional arguments passed to f. The position of the args 
                will be shifted by 1 position with the  user's password is 
                inserted at position 0. 
            **kwargs: Keyword arguments passed directly to f.
        """
        self.appWindow.stack(self.pwDialog.withCallback(f, *args, **kwargs))
    def walletFilename(self):
        return self.getNetSetting(currentWallet)
    def sysTrayActivated(self, trigger):
        """
        Qt Slot called when the user interacts with the system tray icon. Shows 
        the window, creating an icon in the user's application panel that 
        persists until the appWindow is minimized.
        """
        if trigger == QtWidgets.QSystemTrayIcon.Trigger:
            self.appWindow.show()
            self.appWindow.activateWindow()
    def minimizeApp(self, *a):
        """
        Minimizes the application. Because TinyDecred is a system-tray app, the
        program does not halt execution, but the icon is removed from the 
        application panel. Any arguments are ignored.
        """
        self.appWindow.close()
        self.appWindow.hide()
    def netDirectory(self):
        """
        The application's network directory.

        Returns:
            str: Absolute filepath of the directory for the selected network.
        """
        return os.path.join(config.DATA_DIR, cfg.net.Name)
    def loadSettings(self):
        """
        Load settings from the TinyConfig. 
        """
        settings = self.settings = cfg.get("settings")
        if not settings:
            self.settings = settings = {}
            cfg.set("settings", self.settings)
        for k, v in (("theme", Q.LIGHT_THEME), ):
            if k not in settings:
                settings[k] = v
        netSettings = self.getNetSetting()
        # if currentWallet not in netSettings:
        netSettings[currentWallet] = os.path.join(self.netDirectory(), WALLET_FILE_NAME)
        helpers.mkdir(self.netDirectory())
        cfg.save()
    def saveSettings(self):
        """
        Save the current settings.
        """
        cfg.save()
    def getSetting(self, *keys):
        """
        Get the setting using recursive keys.
        """
        return cfg.get("settings", *keys)
    def getNetSetting(self, *keys):
        """
        Get the network-specific setting using recursive keys.
        """
        return cfg.get("networks", cfg.net.Name, *keys)
    def setNetSetting(self, k, v):
        """
        Set the network setting for the currently loaded network.
        """
        cfg.get("networks", cfg.net.Name)[k] = v
    def registerSignal(self, sig, cb, *a, **k):
        """
        Register the receiver with the signal registry.

        The callback arguments will be preceeded with any signal-specific 
        arguments. For example, the BALANCE_SIGNAL will have `balance (float)` 
        as its first argument, followed by unpacking *a.
        """
        if sig not in self.signalRegistry:
            self.signalRegistry[sig] = []
        # elements at indices 1 and 3 are set when emitted
        self.signalRegistry[sig].append((cb, [], a, {},  k))
    def emitSignal(self, sig, *sigA, **sigK):
        """
        Emit a notification of type `sig`.

        Args:
            sig (str): A notification identifier registered with the 
                signalRegistry.
        """
        sr = self.signalRegistry
        if sig not in sr:
            # log.warning("attempted to call un-registered signal %s" % sig)
            return
        for s in sr[sig]:
            sa, sk = s[1], s[3]
            sa.clear()
            sa.extend(sigA)
            sk.clear()
            sk.update(sigK)
            self.qRawSignal.emit(s)
    def signal_(self, s):
        """
        A Qt Slot used for routing signalRegistry signals.

        Args:
            s (tuple): A tuple of (func, signal args, user args, signal kwargs, 
                user kwargs). 
        """
        cb, sigA, a,  sigK, k = s
        cb(*sigA, *a, **sigK, **k)
    def setWallet(self, wallet):
        """
        Set the current wallet.

        Args:
            wallet (Wallet): The wallet to use.
        """
        self.wallet = wallet
        self.emitSignal(ui.BALANCE_SIGNAL, wallet.balance())
        self.tryInitSync()
    def withUnlockedWallet(self, f, cb, *a, **k):
        """
        Run the provided function with the wallet open. This is the preferred
        method of wallet interaction, since the context is properly managed, 
        i.e. the account is locked, unlocked appropriately and the mutex is 
        used to ensure sequential access.

        Args:
            f (func(Wallet, ...)): A function to run with the wallet open. The 
                first argument provided to `f` will be the open wallet. 
            cb (func): A callback to receive the return value from `f`. 
            *a: (optional) Additional arguments to provide to `f`.
            **k: (optional) Additional keyword arguments to provide to `f`.
        """
        # step 1 receives the user password.
        def step1(pw, cb, a, k):
            if pw:
                self.waitThread(step2, cb, pw, a, k)
            else:
                self.appWindow.showError("password required to open wallet")
        # step 2 receives the open wallet.
        def step2(pw, a, k):
            self.emitSignal(ui.WORKING_SIGNAL)
            try:
                with self.wallet.open(0, pw, self.dcrdata, self.blockchainSignals) as w:
                    r = f(w, *a, **k)
                    self.appWindow.pop(self.waitingScreen)
                    self.appWindow.pop(self.pwDialog)
                    return r
            except Exception as e:
                log.warning("exception encountered while performing wallet action: %s" % formatTraceback(e))
                self.appWindow.showError("error")
            finally:
                self.emitSignal(ui.DONE_SIGNAL)
            return False
        self.getPassword(step1, cb, a, k)
    def tryInitSync(self):
        """
        If conditions are right, start syncing the wallet. 
        """
        wallet = self.wallet
        if wallet and wallet.openAccount and self.dcrdata:
            wallet.lock()
            self.emitSignal(ui.WORKING_SIGNAL)
            self.makeThread(wallet.sync, self.doneSyncing)
    def doneSyncing(self, res):
        """
        The wallet sync is complete. Close and lock the wallet. 
        """
        self.emitSignal(ui.DONE_SIGNAL)
        self.wallet.unlock()
        self.wallet.close()
        self.emitSignal(ui.SYNC_SIGNAL)
    def balanceSync(self, balance):
        """
        A Signal method for the wallet. Emits the BALANCE_SIGNAL.

        Args:
            balance (Balance): The balance to pass to subscribed receivers. 
        """
        self.emitSignal(ui.BALANCE_SIGNAL, balance)
    def initDCR(self):
        """
        Connect to dcrdata. On exception, returns None.
        """
        try:
            self.dcrdata.connect()
            return True
        except Exception as e:
            log.error("unable to initialize dcrdata connection at %s: %s" % (self.dcrdata.baseURI, formatTraceback(e)))
            return None
    def setDCR(self, res):
        """
        Callback to receive return value from initDCR. 
        """
        if not res:
            self.appWindow.showError("No dcrdata connection available.")
            return
        self.tryInitSync()
    def getButton(self, size, text, tracked=True):
        """
        Get a button of the requested size. 
        Size can be one of [TINY, SMALL,MEDIUM, LARGE].
        The button is assigned a style in accordance with the current template.
        By default, the button is tracked and appropriately updated if the 
        template is updated.

        Args
            size (str): One of [TINY, SMALL,MEDIUM, LARGE]
            text (str): The text displayed on the button
            tracked (bool): default True. Whether to track the button. If its a 
                one time use button, as for a dynamically generated dialog, the 
                button should not be tracked.
        """
        button = QtWidgets.QPushButton(text, self.appWindow)
        button.setCursor(QtGui.QCursor(QtCore.Qt.PointingHandCursor))
        if self.settings["theme"] == Q.LIGHT_THEME:
            button.setProperty("button-style-class", Q.LIGHT_THEME)
        if size == TINY:
            button.setProperty("button-size-class", TINY)
        elif size == SMALL:
            button.setProperty("button-size-class", SMALL)
        elif size ==MEDIUM:
            button.setProperty("button-size-class",MEDIUM)
        elif size == LARGE:
            button.setProperty("button-size-class", LARGE)
        if tracked:
            self.trackedCssItems.append(button)
        return button
    def home_(self):
        """
        Go to the home screen.
        """
        self.appWindow.setHomeScreen(self.homeScreen)
    def showMnemonics(self, words):
        """
        Show the mnemonic key. Persist until the user indicates completion.
        """
        screen = screens.MnemonicScreen(self, words)
        self.appWindow.stack(screen)

def loadFonts():
    """
    Load the application font files.
    """
    # see https://github.com/google/material-design-icons/blob/master/iconfont/codepoints
    # for conversions to unicode
    # http://zavoloklom.github.io/material-design-iconic-font/cheatsheet.html
    fontDir = os.path.join(ui.FONTDIR)
    for filename in os.listdir(fontDir):
        if filename.endswith(".ttf"):
            QtGui.QFontDatabase.addApplicationFont(os.path.join(fontDir, filename))

# Some issues responses have indicated that certain exceptions may not be 
# displayed when Qt crashes unless this excepthook redirection is used. 
sys._excepthook = sys.excepthook 
def exception_hook(exctype, value, tb):
    print(exctype, value, tb)
    sys._excepthook(exctype, value, tb) 
    sys.exit(1) 

def runTinyDecred():
    """
    Start the TinyDecred application. 
    """
    sys.excepthook = exception_hook
    QtWidgets.QApplication.setDesktopSettingsAware(False)
    roboFont = QtGui.QFont("Roboto")
    roboFont.setPixelSize(16)
    QtWidgets.QApplication.setFont(roboFont);
    qApp = QtWidgets.QApplication(sys.argv)
    qApp.setStyleSheet(Q.QUTILITY_STYLE)
    qApp.setPalette(Q.lightThemePalette)
    qApp.setWindowIcon(QtGui.QIcon(screens.pixmapFromSvg(DCR.LOGO, 64, 64)))
    qApp.setApplicationName("Tiny Decred")
    loadFonts()

    decred = TinyDecred(qApp)
    try:
        qApp.exec_()
    except Exception as e:
        print(formatTraceback(e))            
    decred.sysTray.hide()
    qApp.deleteLater()
    return


if __name__ == '__main__':
    cfg = config.load()
    # Initialize logging for the entire app.
    logDir = os.path.join(config.DATA_DIR, "logs")
    helpers.mkdir(logDir)
    log = helpers.prepareLogger("APP", os.path.join(logDir, "tinydecred.log"), logLvl=0)
    log.info("configuration file at %s"  % config.CONFIG_PATH)
    log.info("data directory at %s" % config.DATA_DIR)
    runTinyDecred()

