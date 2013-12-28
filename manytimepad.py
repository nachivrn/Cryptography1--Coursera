'''
 There are eleven hex-encoded ciphertexts that are the result of encrypting
 eleven plaintexts with a stream cipher, all with the same stream cipher key.
 Your goal is to decrypt the last ciphertext, and submit the secret message within it as solution.
'''


ct_1 = '315c4eeaa8b5f8aaf9174145bf43e1784b8fa00dc71d885a804e5ee9fa40b16349c146fb778cdf2d3aff021dfff' \
       '5b403b510d0d0455468aeb98622b137dae857553ccd8883a7bc37520e06e515d22c954eba5025b8cc57ee59418ce7dc' \
       '6bc41556bdb36bbca3e8774301fbcaa3b83b220809560987815f65286764703de0f3d524400a19b159610b11ef3e'

ct_2 = '234c02ecbbfbafa3ed18510abd11fa724fcda2018a1a8342cf064bbde548b12b07df44ba7191d9606ef4081ffde5ad46a5' \
       '069d9f7f543bedb9c861bf29c7e205132eda9382b0bc2c5c4b45f919cf3a9f1cb74151f6d551f4480c82b2cb24cc5b028' \
       'aa76eb7b4ab24171ab3cdadb8356f'

ct_3 = '32510ba9a7b2bba9b8005d43a304b5714cc0bb0c8a34884dd91304b8ad40b62b07df44ba6e9d8a2368e51d04e0e7b207b7' \
       '0b9b8261112bacb6c866a232dfe257527dc29398f5f3251a0d47e503c66e935de81230b59b7afb5f41afa8d661cb'

ct_4 = '32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac0' \
       '1a81197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402' \
       'bca670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa'

ct_5 = '32510ba9aab2a8a4fd06414fb517b5605cc0aa0dc91a8908c2064ba8ad5ea06a029056f47a8ad3306ef5021eafe1ac01a8' \
       '1197847a5c68a1b78769a37bc8f4575432c198ccb4ef63590256e305cd3a9544ee4160ead45aef520489e7da7d835402bc' \
       'a670bda8eb775200b8dabbba246b130f040d8ec6447e2c767f3d30ed81ea2e4c1404e1315a1010e7229be6636aaa'

ct_6 = '32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd2061bbde24eb76a19d84aba34d8de287be84d07e7e9a30ee71' \
       '4979c7e1123a8bd9822a33ecaf512472e8e8f8db3f9635c1949e640c621854eba0d79eccf52ff111284b4cc61d11902aebc6' \
       '6f2b2e436434eacc0aba938220b084800c2ca4e693522643573b2c4ce35050b0cf774201f0fe52ac9f26d71b6cf61a711cc' \
       '229f77ace7aa88a2f19983122b11be87a59c355d25f8e4'

ct_7 = '32510bfbacfbb9befd54415da243e1695ecabd58c519cd4bd90f1fa6ea5ba47b01c909ba7696cf606ef40c04afe1ac0aa8148d' \
       'd066592ded9f8774b529c7ea125d298e8883f5e9305f4b44f915cb2bd05af51373fd9b4af511039fa2d96f83414aaaf261bda2e9' \
       '7b170fb5cce2a53e675c154c0d9681596934777e2275b381ce2e40582afe67650b13e72287ff2270abcf73bb028932836fbdecfe' \
       'cee0a3b894473c1bbeb6b4913a536ce4f9b13f1efff71ea313c8661dd9a4ce'

ct_8 = '315c4eeaa8b5f8bffd11155ea506b56041c6a00c8a08854dd21a4bbde54ce56801d943ba708b8a3574f40c00fff9e00fa1439f' \
       'd0654327a3bfc860b92f89ee04132ecb9298f5fd2d5e4b45e40ecc3b9d59e9417df7c95bba410e9aa2ca24c5474da2f276baa' \
       '3ac325918b2daada43d6712150441c2e04f6565517f317da9d3'

ct_9 = '271946f9bbb2aeadec111841a81abc300ecaa01bd8069d5cc91005e9fe4aad6e04d513e96d99de2569bc5e50eeeca709b50a8a987' \
       'f4264edb6896fb537d0a716132ddc938fb0f836480e06ed0fcd6e9759f40462f9cf57f4564186a2c1778f1543efa270bda5e933421' \
       'cbe88a4a52222190f471e9bd15f652b653b7071aec59a2705081ffe72651d08f822c9ed6d76e48b63ab15d0208573a7eef027'

ct_10 = '466d06ece998b7a2fb1d464fed2ced7641ddaa3cc31c9941cf110abbf409ed39598005b3399ccfafb61d0315fca0a314be138a9f3' \
        '2503bedac8067f03adbf3575c3b8edc9ba7f537530541ab0f9f3cd04ff50d66f1d559ba520e89a2cb2a83'

target_ct = '32510ba9babebbbefd001547a810e67149caee11d945cd7fc81a05e9f85aac650e9052ba6a8cd8257bf14d13e6f0a803b54fd' \
            'e9e77472dbff89d71b57bddef121336cb85ccb8f3315f4b52e301d16e9f52f904'

ct_list = [ct_1, ct_2, ct_3, ct_4, ct_5, ct_6, ct_7, ct_8, ct_9, ct_10]
hex_decoded_ct_list = [i.decode('hex') for i in ct_list]
hex_decoded_target = target_ct.decode('hex')

def init_messages_with_blanks():
    target_len = len(hex_decoded_target)
    message_lists = [['_']*target_len for i in hex_decoded_ct_list]
    return message_lists


def build_valid_ascii_with_space_dict():
    valid_ascii_texts = range(ord("a"), ord("z") + 1) + range(ord("A"), ord("Z") + 1)
    texts_dict = {}
    for i in valid_ascii_texts:
        x = strxor(chr(i), " ")
        if x not in texts_dict:
            texts_dict[x] = {}
            texts_dict[x] = (chr(i), " ")
    return texts_dict


def map_xor_result(xor_result, ascii_space_dict, message_list, ct_index1):
    xor_result = xor_result[:len(hex_decoded_target)]
    for i in xrange(len(hex_decoded_target)):
        if xor_result[i] in ascii_space_dict:
          a, b = ascii_space_dict[xor_result[i]]
          if message_list[ct_index1][i] == "_":
            message_list[ct_index1][i] = a
          elif message_list[ct_index1][i] == a:
            continue
          else:
            message_list[ct_index1][i] = ' '


def decrypt(ascii_space_dict, messages):
    for i in range(0, 10):
        for j in range(0, 10):
            if i != j:
                xor_result = strxor(hex_decoded_ct_list[i], hex_decoded_ct_list[j])
                map_xor_result(xor_result, ascii_space_dict, messages, i)

def strxor(a, b):     # xor two strings of different lengths
    if len(a) > len(b):
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a[:len(b)], b)])
    else:
        return "".join([chr(ord(x) ^ ord(y)) for (x, y) in zip(a, b[:len(a)])])

def update_key(derived_key):
    master_key = [''] * len(hex_decoded_target)
    key_xor_1 = strxor(derived_key[0], derived_key[1])
    key_xor_2 = strxor(derived_key[5], derived_key[6])
    for k in xrange(0, len(key_xor_1)):
        if key_xor_1[k] == key_xor_2[k]:
            master_key[k] = derived_key[0][k]
        else:
            master_key[k] = ''

    for k in xrange(0, len(master_key)):
        if master_key[k] != '':
            continue
        for i in xrange(1, 10):
            if i + 1 < 10:
                key_xor = strxor(derived_key[i], derived_key[i+1])
                if key_xor[k] == strxor('a', 'a'):
                    master_key[k] = derived_key[i][k]
                    break
    return ''.join(master_key)

def get_key(messages):
    derived_keys = {}
    for i in xrange(0, 10):
        derived_keys[i] = strxor(hex_decoded_ct_list[i], messages[i])
    return update_key(derived_keys)


def main():
    messages = init_messages_with_blanks()
    ascii_space_dict = build_valid_ascii_with_space_dict()
    decrypt(ascii_space_dict, messages)
    master_key = get_key(messages)
    print strxor(master_key, hex_decoded_target)

if __name__ == '__main__':
    main()
