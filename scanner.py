#notes:
#proposed solutoin: use suffix tree
#
import time
import os
import sys

class SigMatch():
    def __init__(self , signatureId , matchLocation):
        self.signatureId = signatureId
        self.matchLocation = matchLocation

    def getSignatureId(self):
        return self.signatureId

    def getMatchArr(self):
        return self.matchLocation


def parseSignatureDB(sigDir):
    db=[]
    for root , dirs , files in os.walk(sigDir):
        for file in files:
            p = os.path.join(root , file)
            fileAbsPath = os.path.abspath(p)
            ptr = open(fileAbsPath , "rb")
            sig = ptr.read()
            db.append((file , sig,))
    return db


def readBinaryFile(fileName):
    src = open(fileName , "rb")
    dump = src.read()
    return dump


def kmp_matcher(binFile, patternTuple):
    pattern = patternTuple[1]
    res = []
    n=len(binFile)
    m=len(pattern)
    pi = calc_prefix(pattern)
    cnt = 0
    i = 0
    while i < n:
        if pattern[cnt]==binFile[i]:
            cnt += 1
            i += 1
        else:
            if cnt != 0:
                cnt = pi[cnt-1]
            else:
                i += 1
        if cnt == m:
            res.append(str(i-cnt))
            cnt = pi[cnt-1]
            break # break at the first occurance of a sig match
    return res


def calc_prefix(pr):
    arrLen=len(pr)
    pi =range(arrLen)
    j = 1
    l = 0
    while j < arrLen:
        if pr[j] < pr[l]:
            l += 1
            pi[j] = l
            j += 1
        else:
            if l != 0:
                l = pi[l-1]
            else:
                pi[j] = 0
                j += 1
    return pi


def scanFile(binFile , pattern):
    finalRes = []
    target = readBinaryFile(binFile)
    counter = 0
    for patternIternation in pattern:
        matchRes = kmp_matcher(target, patternIternation)
        if len(matchRes) > 0:
            finalRes.append(SigMatch(patternIternation[0] , matchRes))

    return finalRes


if __name__=="__main__":
    #usage: python AntiVirus.py [directory] [signatureDB]
    targetDir = sys.argv[1]
    sigFile = sys.argv[2]
    st = time.time()
    pattern = parseSignatureDB(sigFile)

    for root , dirs , files in os.walk(targetDir):
        for file in files:
            p = os.path.join(root , file)
            fileAbsPath = os.path.abspath(p)
            scanRes = scanFile( fileAbsPath, pattern)
            if len(scanRes) > 0:
                print "------------------------------------------------------------------------"
                print fileAbsPath
            for item in scanRes:
                print "SigID:" , item.getSignatureId() , "found at Byte:" , item.getMatchArr()[0]

    print "------------------------------------------------------------------------"
    print "TOTAL TIME:" , time.time() - st
