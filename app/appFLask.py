from flask import request, Flask, jsonify
import psycopg2
import os
import pandas as pd
import random 
from flask_cors import CORS
from datetime import datetime
from limpieza_datos import *


app = Flask(__name__)
app.config["DEBUG"] = True
CORS(app)

def malware_type_detection(dict):
    if 'FILENAME' in dict.keys():
        clean_data_phishing(dict)
    elif 'Destination Port' in dict.keys():
        clean_data_ddos(dict)
    else:
        clean_data_login(dict)

def procesamiento_datos():
    login_list =[]
    df_int_login = pd.read_csv("https://desafiogrupo1.s3.us-east-1.amazonaws.com/df1_alimentacion_login.csv")
    df_ddos = pd.read_csv("https://desafiogrupo1.s3.us-east-1.amazonaws.com/df_alimentacion_DDOS.csv")
    df_phishing = pd.read_csv("https://desafiogrupo1.s3.us-east-1.amazonaws.com/df_alimentacion_phising.csv")

    for i in range(df_int_login.shape[0]):
        login_list.append(df_int_login.iloc[i].to_dict())

    for i in range(df_ddos.shape[0]):
        login_list.append(df_ddos.iloc[i].to_dict())

    for i in range(df_phishing.shape[0]):
        login_list.append(df_phishing.iloc[i].to_dict())

    random.shuffle(login_list)

    for i in range(len(login_list)):
        malware_type_detection(login_list[i])
    return "Success"
    

@app.route("/", methods= ["GET"])
def main():
    return jsonify(procesamiento_datos())


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)
