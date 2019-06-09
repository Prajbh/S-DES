import time

#declaring standard values

IP = [2, 6, 3, 1, 4, 8, 5, 7]
EP_BIT = [4, 1, 2, 3, 2, 3, 4, 1]
IP_INVERSE = [4, 1, 3, 5, 7, 2, 8, 6]
PC_1 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
PC_2 = [6, 3, 7, 4, 8, 5, 10, 9]
P = [2, 4, 3, 1]

mat1 = [[1, 0, 3, 2],
      [3, 2, 1, 0],
      [0, 2, 1, 3],
      [3, 1, 3, 2]]

mat2 = [[0, 1, 2, 3],
      [2, 0, 1, 3],
      [3, 0, 1, 0],
      [2, 1, 0, 3]]

KEY = '1011101001'

#function to permutate 
def permutate(listname, fixed):
        result = []
        for i in fixed:
                result.append(listname[i])
        return result

#function to xor the values
def xor(left,right):
	result = []
	j = len(left)-1
	for i in range(0, len(left)):
		result.append(int(left[j])^int(right[j]))
		j = j - 1
	return result[::-1]

#function to find keys	
def find_key(K,n):
        for i in range(0,n):
                K1 = K[0:5]
                K2 = K[5:10]
                K1.insert(4,K1.pop(0))
                K2.insert(4,K2.pop(0))
                K = K1 + K2
        result_K = permutate(K,[5,2,6,3,7,4,9,8])
        return result_K

#encryption function		 
def encrypt(right,K):
        m = permutate( right,[3,0,1,2,1,2,3,0])
        eResult = xor(m,K)
        block1 = eResult[0:4]
        block2 = eResult[4:8]
        S3 = [[1,0,3,2],[3,2,1,0],[0,2,1,3],[3,1,3,2]]
        S4 = [[0,1,2,3],[2,0,1,3],[3,0,1,0],[2,1,0,3]]
        temp_s1r = int(str(block1[0])+str(block1[3]),2)
        temp_s1c = int(str(block1[1])+str(block1[2]),2)
        S1 = S3[temp_s1r][temp_s1c]
        temp_s2r = int(str(block2[0])+str(block2[3]),2)
        temp_s2c = int(str(block2[1])+str(block2[2]),2)
        S2 = S4[temp_s2r][temp_s2c]
        S1 = list(format(S1,"#02b")[2:])
        S2 = list(format(S2,"#02b")[2:])
        if len(S1) == 1:
                S1.insert(0,0)
        if len(S2) == 1:
                S2.insert(0,0)
        P_temp = S1 + S2
        P = permutate(P_temp,[1,3,2,0])
        return P

def des(left,right,K):
        operate = encrypt(right,K)
        left = xor(left,operate)
        return left, right

#decryption
def decrypt(ip,key1,key2):
        ip = permutate(ip,[1,5,2,0,3,7,4,6])
        left = ip[0:4]
        right = ip[4:8]
        right,left = des(left,right,key1)
        right,left = des(left,right,key2)
        result = right + left
        output = permutate(result,[3,0,2,4,6,1,7,5])
        return output

#bruteforce 
def bruteForce(keys1,plain,encrypt):
        keyset = []
        for i in keys1:
                K1 = i[0]
                K2 = i[1]
                K1 = permutate(K1,[2,4,1,6,3,9,0,8,7,5])
                K2 = permutate(K2,[2,4,1,6,3,9,0,8,7,5])
                key1_c = find_key(K1,1)
                key2_c = find_key(K1,3)
                output_encrypt = decrypt(plain,key1_c,key2_c)
                key1_c = find_key(K2,1)
                key2_c = find_key(K2,3)
                output_encrypt2 = decrypt(output_encrypt,key1_c,key2_c)
                if encrypt == output_encrypt2:
                        keyset.append(i)
        return keyset


#to generate the keys 
K = [1, 0, 1, 1, 1, 0, 1, 0, 0, 1]
keyset = permutate(K,[2,4,1,6,3,9,0,8,7,5])
key1 = find_key(keyset,1)
key2 = find_key(keyset,3)

#decrypting

inputList = [0,0,0,1,1,1,0,0]
output = decrypt(inputList,key1,key2)

print ("plaintext\n",inputList)
print ("after first encryption\n",output)

#for double sdes
K = [0, 1, 1, 1, 0, 1, 1, 0, 1, 0]
keyset = permutate(K,[2,4,1,6,3,9,0,8,7,5])
key3 = find_key(keyset,1)
key4 = find_key(keyset,3)

output3 = decrypt(output,key3,key4)
print ("After encrypting for the second time\n",output3)


#deencrypting
output2 = decrypt(output3,key4,key3)
output1 = decrypt(output2,key2,key1)

# code to collect all the keys
a = '0000000000'
b = '0000000001'

allKeys = []
allKeys.append([0,0,0,0,0,0,0,0,0,0])

#collecting all keys in the range 1 to 2^10

for i in range(1,2**10):
        c = list(bin(int(a,2)+int(b,2))[2:])
        if len(c) < 10:
                for j in range(0,10 - len(c)):
                        c.insert(j,"0")
        a = "".join(c)
        m = list(a)
        res = []
        for k in m:
                res.append(int(k))
        allKeys.append(res)

allKeys.append(res)

# meet in the middle attack

timeStart = time.time()

input_c = [0,1,1,0,1,0,1,1]
inputList_d = [1,1,0,0,1,0,0,0]
aencrypt = []
for key1 in allKeys:
        keyset = permutate(key1,[2,4,1,6,3,9,0,8,7,5])
        key1_c = find_key(keyset,1)
        key2_c = find_key(keyset,3)
        output = decrypt(input_c,key1_c,key2_c)
        aencrypt.append(output)

ks = []
count = 0
adecrypt = []
for key2 in allKeys:
        keyset = permutate(key2,[2,4,1,6,3,9,0,8,7,5])
        key1_c = find_key(keyset,1)
        key2_c = find_key(keyset,3)
        output = decrypt(inputList_d,key2_c,key1_c)
        adecrypt.append(output)

count = 0
for m,i in enumerate(aencrypt):
        for n,j in enumerate (adecrypt):
                if i == j:
                        ks.append([allKeys[m],allKeys[n]])
                        
#print(len(ks))
#given plaintext and ciphertext
plaintext = [[1,0,0,1,0,1,1,0],[0,0,1,0,1,0,1,1],[1,0,1,0,1,0,1,0],[0,0,0,1,1,1,0,0]]
ciphertext = [[0,0,0,0,0,1,1,1],[0,0,0,1,0,0,1,0],[1,0,0,1,1,0,1,1],[1,0,1,0,0,0,0,0]]

for m,i in enumerate(plaintext):
        ks = bruteForce(ks,i,ciphertext[m])

timeEnd = time.time()
totalTime = timeEnd - timeStart
print ("The total time taken for MITM attack\n",totalTime)

#---------------------------------------
#code to find the keys using brute force
timeStart = time.time()

input_c = [0,1,1,0,1,0,1,1]
inputList_d = [1,1,0,0,1,0,0,0]
keys = []
for ki1 in allKeys:
        keyset_c = permutate(ki1,[2,4,1,6,3,9,0,8,7,5])
        key1_c = find_key(keyset_c,1)
        key2_c = find_key(keyset_c,3)
        output_encrypt = decrypt(input_c,key1_c,key2_c)
        for ki2 in allKeys:
                keyset_c = permutate(ki2,[2,4,1,6,3,9,0,8,7,5])
                key1_c = find_key(keyset_c,1)
                key2_c = find_key(keyset_c,3)
                output_encrypt2 = decrypt(output_encrypt,key1_c,key2_c)
                if output_encrypt2 == inputList_d:
                        keys.append([ki1,ki2])

plaintext = [[1,0,0,1,0,1,1,0],[0,0,1,0,1,0,1,1],[1,0,1,0,1,0,1,0],[0,0,0,1,1,1,0,0]]
ciphertext = [[0,0,0,0,0,1,1,1],[0,0,0,1,0,0,1,0],[1,0,0,1,1,0,1,1],[1,0,1,0,0,0,0,0]]

for m,i in enumerate(plaintext):
        keys = bruteForce(keys,i,ciphertext[m])

timeEnd = time.time()
totalTime = timeEnd - timeStart
print ("The total time taken for brute force\n",totalTime)
        
#-----------------------------------------
#
ip_cbc = '1101000001100110100110011100001101010010001110000111010100001011111101101110101111010001101100110011111100101000111010100001001100101101110100101100101100100011011101010000101101110010011010111100000110000001111110101100010100110001010110100110101001000000'
ip_cbc = list(ip_cbc)
input_cbc = []
ip = []
for i, j in enumerate(ip_cbc):
        ip.append(int(j))
        if len(ip) == 8:
                input_cbc.append(ip)
                ip = []
K1 = keys[0][1]
K2 = keys[0][1]
K1 = permutate(K1,[2,4,1,6,3,9,0,8,7,5])
K2 = permutate(K2,[2,4,1,6,3,9,0,8,7,5])
key1 = find_key(K1,1)
key2 = find_key(K1,3)
key3 = find_key(K2,1)
key4 = find_key(K2,3)

pt_cbc = []
IV = [1,0,0,1,1,1,0,0]
for i in input_cbc:
        output = decrypt(i,key4,key3)
        output3 = decrypt(output,key2,key1)
        pt = xor(IV,output3)
        pt_cbc.append(pt)
        IV = output3

binary_format = ""
for i in pt_cbc:
        for j in i:
                binary_format = binary_format + str(j)
print ("The key value pair is (k1,k2):\n", keys)
print ("The decryption of the text encrypted using CBC mode is\n", binary_format)