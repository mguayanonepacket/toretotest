import sys
i=0
args=[]
if len(sys.argv) > 1:
    # Imprimir los argumentos
    args=sys.argv[1].split(' ')
    for arg in args:
        print(f"argumento {i}: {arg}")
        i+=1
else:
    print("No se pasaron argumentos.")

x=input('who are you?:')
print(f'you are {x}')
