from copy import deepcopy
import os
import itertools
import numpy as np
import sys
from sys import platform
from collections import OrderedDict
import string
import re
import unicodedata
import itertools
import multiprocessing
from math import log
import difflib

def encC(texto,  chave, modo):
    texto_encript = ''
    alphamat = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
                'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
                'U', 'V', 'W', 'X', 'Y', 'Z', 'Á', 'É', 'Í', 'Ó',
                'Ú', 'Ã', 'Õ', 'Â', 'Ê', 'Î', 'Ô', 'Û', '0', '1',
                '2', '3', '4', '5', '6', '7', '8', '9', 'Ç', '!',
                '@', '#', '$', '%', '"', '&', '*', '(', ')', '-',
                ',', '.', '<', '>', '/', '\\', 'ç', ':', '{', '}',
                '\'', ';', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h',
                'i', 'j', 'k', 'j', 'k', 'l', 'm', 'n', 'o', 'p',
                'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

    alphamat.sort()

    alphabet=list(alphamat)
    texto_list = list(texto);

    for char in texto_list:
        indice = alphabet.index(char)
        if indice+chave <= 99:
            texto_encript = texto_encript + str(alphabet[indice+chave])
        else:
            texto_encript = texto_encript + str(alphabet[(indice+chave)-100])


    return "".join(texto_encript)
def main():
    # dir, filename = os.path.split(path)
    # filename, ext = os.path.splitext(filename)
    # metricsfile = str("/files_info/")+str(filename)+str(".mm")
    while True:
        cifrar = str(input("arquivo para cifrar: \n"))
        cifrado = open(cifrar, "rb")
        cif = cifrar_fd.read()
        cif= cif.replace(' ','')
        cif= cif.replace('[','{')
        cif= cif.replace(']','}')
        cif= cif.replace('?','')
        cif= cif.replace('_','')
        cif= cif.replace("\n",'')
        cif= cif.replace("\b",'')
        txt_cifrado=ascii(cif)
        txt_cifrado=encC(txt_cifrado,7,0)
        cifrado.write(txt_cifrado)
        cifrado.close()
        sleep(10)


if __name__ == '__main__':
    main()
