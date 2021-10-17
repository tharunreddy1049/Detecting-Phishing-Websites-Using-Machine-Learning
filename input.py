import numpy as np import matplotlib.pyplot as plt import pandas as pd 
from sklearn.ensemble import RandomForestClassifier from sklearn.externals import joblib 
#importing the dataset 
dataset = pd.read_csv("datasets/phishcoop.csv") dataset = dataset.drop('id', 1) #removing unwanted column x = dataset.iloc[ : , :-1].values y = dataset.iloc[:, -1:].values 
#spliting the dataset into training set and test set from sklearn.model_selection import train_test_split x_train, x_test, y_train, y_test = train_test_split(x,y,test_size = 0.25, random_state = 42 ) 
# ----------------applying grid search to find best performing parameters from sklearn.model_selection import GridSearchCV 
parameters = [{'n_estimators': [100, 700], 'max_features': ['sqrt', 'log2']}] 
# 'criterion' :['gini', 'entropy']}] 
grid_search = GridSearchCV(RandomForestClassifier(), parameters,cv =5, n_jobs= -1) grid_search.fit(x_train, y_train.ravel()) 
#printing best parameters 
print("Best Accurancy =" +str( grid_search.best_score_)) print("best parameters =" + str(grid_search.best_params_)) #fitting RandomForest regression with best params 
classifier = RandomForestClassifier(n_estimators = 100, max_features = 'log2', random_state = 0) classifier.fit(x_train, y_train.ravel()) from sklearn.metrics import mean_squared_error 
#predicting the tests set result y_pred = classifier.predict(x_test) #confusion matrix 
from sklearn.metrics import confusion_matrix cm = confusion_matrix(y_test, y_pred) print(cm) from sklearn.ensemble import RandomForestRegressor forest_regressor = RandomForestRegressor() forest_reg = RandomForestRegressor() forest_reg.fit(x_train,y_train) prediction = forest_reg.predict(x_test) rmse = mean_squared_error(y_pred,y_test.ravel()) print(rmse) 
#pickle file joblib 
# joblib.dump(classifier, 'final_models/rf_final.pkl') 
# #-------------Features Importance random forest 
# names = dataset.iloc[:,:-1].columns 
# importances =classifier.feature_importances_ 
# sorted_importances = sorted(importances, reverse=True) 
# indices = np.argsort(-importances) 
# var_imp = pd.DataFrame(sorted_importances, names[indices], columns=['importance']) 
#-------------plotting variable importance 
# plt.title("Variable Importances") 
# plt.barh(np.arange(len(names)), sorted_importances, height = 0.7) 
# plt.yticks(np.arange(len(names)), names[indices], fontsize=7) 
# plt.xlabel('Relative Importance') 
# plt.show() 
Inputscript.py – This script is used to extract all the features from a url and feed it into the machine learning model inside a pickle file. 
import re 
from tldextract import extract import ssl import socket 
from bs4 import BeautifulSoup import urllib.request import whois import datetime 
import requests try: response = requests.get(url) except: 
response = "" def url_having_ip(url): # using regular function 
symbol = re.findall(r'(http((s)?)://)((((\d)+).)*)((\w)+)(/((\w)+))?',url) if(len(symbol)!=0): having_ip = 1 #phishing else: 
having_ip = -1 #legitimate return(having_ip) # return 0 def url_length(url): length=len(url) if(length<54): return -1 elif(54<=length<=75): 
return 0 else: return 1 def url_short(url): if re.findall("goo.gl|bit.ly", url): 
return 1 else: return -1 def having_at_symbol(url): symbol=re.findall(r'@',url) if(len(symbol)==0): 
return -1 else: return 1 def doubleSlash(url): if(url.count('//') > 1): 
return 1 else: return -1 def prefix_suffix(url): 
subDomain, domain, suffix = extract(url) if(domain.count('-')): 
return 1 else: return -1 def sub_domain(url): 
subDomain, domain, suffix = extract(url) if(subDomain.count('.')==0): 
return -1 elif(subDomain.count('.')==1): 
return 0 else: return 1 def SSLfinal_State(url): try: 
#check wheather contains https if(re.search('^https',url)): 
usehttps = 1 else: 
usehttps = 0 
#getting the certificate issuer to later compare with trusted issuer 
#getting host name 
subDomain, domain, suffix = extract(url) host_name = domain + "." + suffix context = ssl.create_default_context() 
sct = context.wrap_socket(socket.socket(), server_hostname = host_name) sct.connect((host_name, 443)) 
certificate = sct.getpeercert() 
issuer = dict(x[0] for x in certificate['issuer']) certificate_Auth = str(issuer['commonName']) certificate_Auth = certificate_Auth.split() if(certificate_Auth[0] == "Network" or certificate_Auth == "Deutsche"): 
certificate_Auth = certificate_Auth[0] + " " + certificate_Auth[1] else: 
certificate_Auth = certificate_Auth[0] trusted_Auth = 
['Comodo','Symantec','GoDaddy','GlobalSign','DigiCert','StartCom','Entrust','Ve rizon','Trustwave','Unizeto','Buypass','QuoVadis','Deutsche Telekom','Network 
Solutions','SwissSign','IdenTrust','Secom','TWCA','GeoTrust','Thawte','Doster',' 
VeriSign'] 
#getting age of certificate 
startingDate = str(certificate['notBefore']) endingDate = str(certificate['notAfter']) startingYear = int(startingDate.split()[3]) endingYear = int(endingDate.split()[3]) 
Age_of_certificate = endingYear-startingYear 
#checking final conditions if((usehttps==1) and (certificate_Auth in trusted_Auth) and (Age_of_certificate>=1) ): 
return -1 #legitimate elif((usehttps==1) and (certificate_Auth not in trusted_Auth)): 
return 0 #suspicious else: 
return 1 #phishing except Exception as e: 
return 1 def domain_registration(url): try: 
w = whois.whois(url) updated = w.updated_date exp = w.expiration_date length = (exp[0]-updated[0]).days if(length<=365): 
return 1 else: 
return -1 except: return 0 def favicon(url): 
return 0 def port(url): 
return 0 def https_token(url): 
subDomain, domain, suffix = extract(url) host =subDomain +'.' + domain + '.' + suffix if(host.count('https')): #attacker can trick by putting https in domain part return 1 else: 
return -1 def request_url(url): try: 
subDomain, domain, suffix = extract(url) websiteDomain = domain 
opener = urllib.request.urlopen(url).read() soup = BeautifulSoup(opener, 'lxml') imgs = soup.findAll('img', src=True) total = len(imgs) linked_to_same = 0 avg =0 for image in imgs: 
subDomain, domain, suffix = extract(image['src']) imageDomain = domain if(websiteDomain==imageDomain or imageDomain==''): 
linked_to_same = linked_to_same + 1 vids = soup.findAll('video', src=True) total = total + len(vids) for video in vids: 
subDomain, domain, suffix = extract(video['src']) vidDomain = domain if(websiteDomain==vidDomain or vidDomain==''): linked_to_same = linked_to_same + 1 linked_outside = total-linked_to_same if(total!=0): 
avg = linked_outside/total if(avg<0.22): 
return -1 elif(0.22<=avg<=0.61): 
return 0 else: return 1 except: return 0 def url_of_anchor(url): try: 
subDomain, domain, suffix = extract(url) websiteDomain = domain 
opener = urllib.request.urlopen(url).read() soup = BeautifulSoup(opener, 'lxml') anchors = soup.findAll('a', href=True) total = len(anchors) linked_to_same = 0 avg = 0 for anchor in anchors: subDomain, domain, suffix = extract(anchor['href']) anchorDomain = domain if(websiteDomain==anchorDomain or anchorDomain==''): 
linked_to_same = linked_to_same + 1 linked_outside = total-linked_to_same if(total!=0): 
avg = linked_outside/total if(avg<0.31): 
return -1 
elif(0.31<=avg<=0.67): 
return 0 else: return 1 except: return 0 def Links_in_tags(url): 
try: 
opener = urllib.request.urlopen(url).read() soup = BeautifulSoup(opener, 'lxml') no_of_meta =0 no_of_link =0 no_of_script =0 anchors=0 avg =0 for meta in soup.find_all('meta'): no_of_meta = no_of_meta+1 for link in soup.find_all('link'): no_of_link = no_of_link +1 for script in soup.find_all('script'): no_of_script = no_of_script+1 for anchor in soup.find_all('a'): 
anchors = anchors+1 
total = no_of_meta + no_of_link + no_of_script+anchors tags = no_of_meta + no_of_link + no_of_script if(total!=0): 
avg = tags/total if(avg<0.25): 
return -1 elif(0.25<=avg<=0.81): 
return 0 else: return 1 except: return 0 def sfh(url): return 0 def email_submit(url): try: 
opener = urllib.request.urlopen(url).read() soup = BeautifulSoup(opener, 'lxml') if(soup.find('mailto:')): 
return 1 else: return -1 except: return 0 def abnormal_url(url): 
return 0 def redirect(url): 
return 0 def on_mouseover(url): if re.findall("<script>.+onmouseover.+</script>", response.text): 
return 1 else: return -1 def rightClick(url): if re.findall(r"event.button ?== ?2", response.text): 
return 1 else: return -1 def popup(url): if re.findall(r"alert\(", response.text): 
return 1 else: return -1 def iframe(url): if re.findall(r"[<iframe>|<frameBorder>]", response.text): return 1 else: 
return -1 def age_of_domain(url): try: 
w = whois.whois(url) start_date = w.creation_date current_date = datetime.datetime.now() age =(current_date-start_date[0]).days if(age>=180): 
return -1 else: return 1 except Exception as e: 
print(e) return 0 
#the below modules are not possible as the google has removed the api for google page_rank and other indexing system 
#therefore 0 has been inserted as default values. def dns(url): 
return 0 def web_traffic(url): 
return 0 def page_rank(url): #Not possible return 0 def google_index(url): #Not possible return 0 def links_pointing(url): #Not possible return 0 def statistical(url): #Not possible return 0 
def main(url): 
check = 
[[url_having_ip(url),url_length(url),url_short(url),having_at_symbol(url), doubleSlash(url),prefix_suffix(url),sub_domain(url),SSLfinal_State(url), domain_registration(url),favicon(url),port(url),https_token(url),request_url(url) , url_of_anchor(url),Links_in_tags(url),sfh(url),email_submit(url),abnormal_url(u rl), redirect(url),on_mouseover(url),rightClick(url),popup(url),iframe(url), age_of_domain(url),dns(url),web_traffic(url),page_rank(url),google_index(url), links_pointing(url),statistical(url)]] print(check) return check 
