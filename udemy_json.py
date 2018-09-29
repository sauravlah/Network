import json
import os

data = json.load(open("data.json", 'r'))

def translate(w):
    return data(w)

word = input("Please type in the word for which you are looking for a meaning")
print (translate(word))
x