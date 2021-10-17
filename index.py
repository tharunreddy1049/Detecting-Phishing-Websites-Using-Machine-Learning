import joblib import inputscript 
 
 
classifier = joblib.load('rf_final.pkl') 
#input urlhttps 
print("Welcome to the phishing website detection software ! \n") print("Enter url:\n") url = input() 
 
checkprediction =inputscript.main(url)  prediction =classifier.predict(checkprediction) print(prediction) 
 
if(prediction == 1): 
    print("The site is a phishing site") else: 
    print("The site is not a phishing site") 
