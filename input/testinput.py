import sys
i=0
if len(sys.argv) > 1:
    # Imprimir los argumentos
    for arg in sys.argv[1:]:
        print(f"argumento {i}: {arg}")
        i+=1
else:
    print("No se pasaron argumentos.")

x=input('who are you?:')
print(f'you are {x}')
