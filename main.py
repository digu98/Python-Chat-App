import eel 
import time
from random import randint 
  
eel.init("web")   
  
# Exposing the random_python function to javascript 
@eel.expose     
def random_python(): 
    print("Random function running") 
    return randint(1,100) 

@eel.expose
def randomList_python():
    conatinerArray = []
    print("Random simulator function running") 
    # conatinerArray.append(randint(1,100))
    return randint(1,100)

# Start the index.html file 
eel.start("index.html")
