"""
Copyright (c) 2019, Brian Stafford
See LICENSE for details

Some network math.
"""
import math
from tinydecred.util import helpers
from tinydecred.pydecred import constants as C, mainnet

NETWORK = mainnet
MODEL_DEVICE = helpers.makeDevice(**C.MODEL_DEVICE)

def makeDevice(model=None, price=None, hashrate=None, power=None, release=None, source=None):
    """
    Create a device
    """
    device = {
        "model": model,
        "price": price,
        "hashrate": hashrate,
        "power": power,
        "release": release,
        "source": source
    }
    device["daily.power.cost"] = C.PRIME_POWER_RATE*device["power"]/1000*24
    device["min.profitability"] = -1*device["daily.power.cost"]/device["price"]
    device["power.efficiency"] = device["hashrate"]/device["power"]
    device["relative.price"] = device["price"]/device["hashrate"]
    if release and isinstance(release, str):
        device["release"] = helpers.mktime(*[int(x) for x in device["release"].split("-")])
    return device


def setNetwork(network):
    global NETWORK
    NETWORK = network


def clamp(val, minVal, maxVal):
    return max(minVal, min(val, maxVal))


def interpolate(pts, x):
    """
    Linearly interpret between points to get an estimate.
    pts should be of the form ((x1,y1), (x2,y2), ..) of increasing x.
    """
    lastPt = pts[0]
    for pt in pts[1:]:
        t, v = pt
        lt, lv = lastPt
        if t >= x:
            return lv + (x - lt)/(t - lt)*(v - lv)
        lastPt = pt


def derivative(pts, x):
    """
    Slope of line between two points. (δy/δx).
    pts should be of the form ((x1,y1), (x2,y2), ..) of increasing x.
    """

    lastPt = pts[0]
    for pt in pts[1:]:
        t, v = pt
        if t >= x:
            lt, lv = lastPt
            return (v - lv)/(t - lt)
        lastPt = pt


def getCirculatingSupply(tBlock):
    """ An approximation based on standard block time of 5 min and timestamp of genesis block """
    if tBlock < NETWORK.GENESIS_STAMP:
        return 0
    premine = 1.68e6
    if tBlock == NETWORK.GENESIS_STAMP:
        return premine
    block2reward = 21.84
    block4096stamp = helpers.mktime(2016, 2, 22)
    if tBlock < block4096stamp:
        return premine + (tBlock - NETWORK.GENESIS_STAMP)/NETWORK.TargetTimePerBlock*block2reward
    block4096reward = 31.20
    regularStamp = NETWORK.GENESIS_STAMP+NETWORK.SubsidyReductionInterval*NETWORK.TargetTimePerBlock
    if tBlock < regularStamp:
        return premine + (tBlock - NETWORK.GENESIS_STAMP)/NETWORK.TargetTimePerBlock*block4096reward
    tRemain = tBlock - regularStamp
    blockCount = tRemain/NETWORK.TargetTimePerBlock
    periods = blockCount/float(NETWORK.SubsidyReductionInterval)
    vSum = 1833321 # supply at start of regular reward period
    fullPeriods = int(periods)
    partialPeriod = periods - fullPeriods
    p = 0
    for p in range(fullPeriods):
        reward = blockReward((p+1)*NETWORK.SubsidyReductionInterval)
        vSum += reward*NETWORK.SubsidyReductionInterval
    p += 1
    reward = blockReward((p+1)*NETWORK.SubsidyReductionInterval)
    vSum += reward*NETWORK.SubsidyReductionInterval*partialPeriod
    return vSum


def timeToHeight(t):
    """
    Approximate the height based on the time.
    """
    return int((t-NETWORK.GENESIS_STAMP)/NETWORK.TargetTimePerBlock)


def binomial(n, k):
    f = math.factorial
    return f(n)/f(k)/f(n-k)


def concensusProbability(stakeportion, winners=None, participation=1):
    """
    This is the binomial distribution form rather than the hypergeometric.
    The two converge at ticketPoolSize >> winners.
    """
    winners = winners if winners else NETWORK.TicketsPerBlock
    halfN = winners/2.
    k = 0
    probability = 0
    while k < halfN:
        probability += binomial(winners, k)*stakeportion**(winners-k)*((1-stakeportion)*participation)**k
        k += 1
    if probability == 0:
        print("Quitting with parameters %s" % repr((stakeportion, winners, participation)))
    return probability


def hashportion(stakeportion, winners=None, participation=1):
    """
    The portion of the blockchain that would need to be under
    attacker control for an attack to be initiated.
    """
    winners = winners if winners else NETWORK.TicketsPerBlock
    return 1 - concensusProbability(stakeportion, winners)


def dailyPowRewards(height, blockTime=None, powSplit=None):
    """
    Approximation of the total daily payout in DCR.
    """
    powSplit = powSplit if powSplit else NETWORK.POW_SPLIT
    blockTime = blockTime if blockTime else NETWORK.TargetTimePerBlock
    return C.DAY/blockTime*blockReward(height)*powSplit


def dailyPosRewards(height, blockTime=None, stakeSplit=None):
    """
    Approximation of the total daily POS rewards.
    """
    stakeSplit = stakeSplit if stakeSplit else NETWORK.STAKE_SPLIT
    blockTime = blockTime if blockTime else NETWORK.TargetTimePerBlock
    return C.DAY/blockTime*blockReward(height)*stakeSplit


def blockReward(height):
    """
    https://docs.decred.org/advanced/inflation/
    I think this is actually wrong for height < 4096
    """
    return 31.19582664*(100/101)**int(height/6144)


class ReverseEquations:
    """
    A bunch of static methods for going backwards from profitability to
    common network parameters
    """
    @staticmethod
    def grossEarnings(device, roi, energyRate=None):
        energyRate = energyRate if energyRate else C.PRIME_POWER_RATE
        return roi*device["price"] + 24*device["power"]*energyRate/1000

    @staticmethod
    def networkDeviceCount(device, xcRate, roi, height=3e5, blockTime=None, powSplit=None):
        powSplit = powSplit if powSplit else NETWORK.POW_SPLIT
        blockTime = blockTime if blockTime else NETWORK.TargetTimePerBlock
        return dailyPowRewards(height, blockTime, powSplit)*xcRate/ReverseEquations.grossEarnings(device, roi)

    @staticmethod
    def networkHashrate(device, xcRate, roi, height=3e5, blockTime=None, powSplit=None):
        powSplit = powSplit if powSplit else NETWORK.POW_SPLIT
        blockTime = blockTime if blockTime else NETWORK.TargetTimePerBlock
        return ReverseEquations.networkDeviceCount(device, xcRate, roi, height, blockTime, powSplit)*device["hashrate"]

    @staticmethod
    def ticketPrice(apy, height, winners=None, stakeSplit=None):
        winners = winners if winners else NETWORK.TicketsPerBlock
        stakeSplit = stakeSplit if stakeSplit else NETWORK.STAKE_SPLIT
        Rpos = stakeSplit*blockReward(height)
        return Rpos/(winners*((apy + 1)**(25/365.) - 1))


class Ay:
    """
    The parametrized cost of attack result.
    """
    def __init__(self, retailTerm, rentalTerm, stakeTerm, ticketFraction):
        self.retailTerm = retailTerm
        self.rentalTerm = rentalTerm
        self.stakeTerm = stakeTerm
        self.workTerm = rentalTerm + retailTerm
        self.attackCost = retailTerm + rentalTerm + stakeTerm
        self.ticketFraction = ticketFraction

    def __str__(self):
        return "<AttackCost: ticketFraction %.3f, workTerm %i, stakeTerm %i, attackCost %i>" % (self.ticketFraction, self.workTerm, self.stakeTerm, self.attackCost)


def attackCost(ticketFraction=None, xcRate=None, blockHeight=None, roi=None,
               ticketPrice=None, blockTime=None, powSplit=None,
               stakeSplit=None, treasurySplit=None, rentability=None,
               nethash=None, winners=None, participation=1.,
               poolSize=None, apy=None, attackDuration=C.HOUR, device=None,
               rentalRatio=None, rentalRate=None
               ):
    """
    Calculate the cost of attack, which is the minimum fiat value of equipment, tickets, and
    rental expenditures required to outpace the main chain.
    
    The cost of attack can be calculated in direct mode or reverse mode, depending on the parameters provided.
    Provide a `nethash` and a `ticketPrice` to calculate in direct mode.
    Omit the `nethash` and `ticketPrice`, and instead provide an `roi` and `apy` to calculate in reverse mode.
    In reverse mode, (xcRate, roi, blockHeight, blockTime, powSplit) are used to calculate a network hashrate,
    and the (apy, blockHeight, winners, stakeSplit) are used to calculate a ticketPrice.

    :param float ticketFraction: required. The fraction of the stakepool under attacker control.
    :param float xcRate: required. The fiat exchange rate.
    :param int blockHeight: required. The height of the blockchain at the time of attack.
    :param roi float: The miner return-on-investment (\alpha). Only used in reverse mode.
    :param  float ticketPrice: The price of the ticket. Providing the ticketPrice causes direct-mode calculation.
    :param int blockTime: The network's target block time. Unix timestamp. Default NETWORK.TargetTimePerBlock
    :param float powSplit: The fraction of the block reward given to the POW miners. Only used in reverse mode.
    :param float stakeSplit: The fraction of the block reward given to the stakeholders. Only used in reverse mode.
    :param float treasurySplit: The fraction of the block reward given to the Decred treasury. Only used in reverse mode.
    :param int rentability: The total hashrate avaialable on the rental market. See also rentalRatio.
    :param int nethash: The network hashrate. Providing the ticketPrice causes direct-mode calculation.
    :param int winners: The number of tickets selected per block. default NETWORK.TicketsPerBlock
    :param float participation: The fraction of stakeholders online and ready to validate.
    :param int poolSize: The network target for ticket pool size. default NETWORK.TicketExpiry
    :param float apy: The annual percentage yield. Used only in reverse mode. apy = (ticketReturnRate + 1)**(365/28)
    :param float attackDuration: The length of the attack, in seconds.
    :param dict device: Device see MODEL_DEVICE and makeDevice for required attributes.
    :param float rentalRatio: An alternative to rentability. The fraction of required hashpower that is available for rent.
    :param float rentalRate: The rental rate, in fiat/hash.
    """
    if any([x is None for x in (ticketFraction, xcRate, blockHeight)]):
        raise Exception("ticketFraction, xcRate, and blockHeight are required args/kwargs for AttackCost")
    blockTime = blockTime if blockTime else NETWORK.TargetTimePerBlock
    winners = winners if winners else NETWORK.TicketsPerBlock
    poolSize = poolSize if poolSize else NETWORK.TicketExpiry
    treasurySplit = treasurySplit if treasurySplit else NETWORK.TREASURY_SPLIT
    if treasurySplit is None:
        raise Exception("AttackCost: treasurySplit cannot be None")

    if stakeSplit:
        if not powSplit:
            powSplit = 1 - treasurySplit - stakeSplit
    else:
        if powSplit:
            stakeSplit = 1 - treasurySplit - powSplit
        else:
            powSplit = NETWORK.POW_SPLIT
            stakeSplit = NETWORK.STAKE_SPLIT

    device = device if device else MODEL_DEVICE
    if nethash is None:
        if roi is None: # mining ROI could be zero 
            raise Exception("minimizeY: Either a nethash or an roi must be provided")
        nethash = ReverseEquations.networkHashrate(device, xcRate, roi, blockHeight, blockTime, powSplit)
    if rentability or rentalRatio:
        if not rentalRate:
            raise Exception("minimizeY: If rentability is non-zero, rentalRate must be provided")
    else:
        rentalRate = 0
    if ticketPrice is None:
        if not apy:
            raise Exception("minimizeY: Either a ticketPrice or an apy must be provided")
        ticketPrice = ReverseEquations.ticketPrice(apy, blockHeight, winners, stakeSplit)
    stakeTerm = ticketFraction*poolSize*ticketPrice*xcRate
    hashPortion = hashportion(ticketFraction, winners, participation)
    attackHashrate = nethash*hashPortion
    rent = rentability if rentability is not None else attackHashrate*rentalRatio if rentalRatio is not None else 0
    rentalPart = min(rent, attackHashrate)
    retailPart = attackHashrate - rentalPart
    rentalTerm = rentalPart*rentalRate/86400*attackDuration
    retailTerm = retailPart*( device["relative.price"] + device["power"]/device["hashrate"]*C.PRIME_POWER_RATE/1000/3600*attackDuration)
    return Ay(retailTerm, rentalTerm, stakeTerm, ticketFraction)


def purePowAttackCost(xcRate=None, blockHeight=None, roi=None, blockTime=None,
                      treasurySplit=None,  rentability=None, nethash=None,
                      attackDuration=C.HOUR, device=None, rentalRatio=None,
                      rentalRate=None, **kwargs):
    if any([x is None for x in (xcRate, blockHeight)]):
        raise Exception("xcRate and blockHeight are required args/kwargs for PurePowAttackCost")
    blockTime = blockTime if blockTime else NETWORK.TargetTimePerBlock
    device = device if device else MODEL_DEVICE
    treasurySplit = treasurySplit if treasurySplit else NETWORK.TREASURY_SPLIT
    if nethash is None:
        if roi is None: # mining ROI could be zero 
            raise Exception("minimizeY: Either a nethash or an roi must be provided")
        nethash = ReverseEquations.networkHashrate(device, xcRate, roi, blockHeight, blockTime, 1-treasurySplit)
    if rentability or rentalRatio:
        if not rentalRate:
            raise Exception("minimizeY: If rentability is non-zero, rentalRate must be provided")
    else:
        rentalRate = 0
    attackHashrate = 0.5*nethash
    rent = rentability if rentability is not None else attackHashrate*rentalRatio if rentalRatio is not None else 0
    rentalPart = min(rent, attackHashrate)
    retailPart = attackHashrate - rentalPart
    rentalTerm = rentalPart*rentalRate/86400*attackDuration
    retailTerm = retailPart*( device["relative.price"] + device["power"]/device["hashrate"]*C.PRIME_POWER_RATE/1000/3600*attackDuration)
    return Ay(retailTerm, rentalTerm, 0, 0)


def minimizeAy(*args, grains=100, **kwargs):
    lowest = C.INF
    result = None
    grainSize = 0.999/grains
    for i in range(1, grains):
        A = attackCost(grainSize*i, *args, **kwargs)
        if A.attackCost < lowest:
            lowest = A.attackCost
            result = A
    return result