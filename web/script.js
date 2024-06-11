document.querySelector("html").onload = function () {  
    // Call python's random_python function 
    eel.randomList_python()(async function(number){   
        // Update the div with a random number returned by python 
        document.querySelector(".random_number").innerHTML += number; 
    }) 
}

document.querySelector("button").onclick = function () {  
    // Call python's random_python function 
    eel.randomList_python()(async function(number){   
        // Update the div with a random number returned by python 
        document.querySelector(".random_number").innerHTML += number; 
    }) 
}