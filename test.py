from tqdm import tqdm
import time
 
print('hello torero')

 
for i in tqdm (range (101), 
               desc="Loading…", 
               ascii=False, ncols=75):
    time.sleep(0.01)
     
print("Complete.")
