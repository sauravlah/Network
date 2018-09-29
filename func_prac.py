def CtoF(temp):
    faren = ((temp * 9/5) + 32)
    if float(faren) < -273.15:
        print ("Sorry this temperature defies laws of Physics. Please input a value more than -273.15.")
    else:
        return (faren)


temperatures=[10, -20, -289, 100]

with open("temperature.txt", 'a+') as ftemp:
    for items in temperatures:
        range = CtoF(items)
        range = str(range)
        ftemp.write(range + '\n')
