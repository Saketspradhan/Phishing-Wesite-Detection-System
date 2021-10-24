import csv
import datetime
import json
import logging
import os
import re
import shutil
import sys
import time
import warnings
from enum import Enum
from logging.handlers import TimedRotatingFileHandler
from random import randint
from tkinter import *
from tkinter import messagebox
from urllib.request import urlopen

import dns
import dns.resolver
import favicon
import joblib
import pandas as pd
import requests
import urlunshort3
import whois
from bs4 import BeautifulSoup
from dateutil.relativedelta import relativedelta

warnings.filterwarnings("ignore")

from PIL import Image, ImageTk

root = Tk()
root.title('Phishing Website Detection Tool')
# root.iconbitmap('C:/Users/saket/Downloads/favicon.ico')


def submitButton():
    global already_submitted
    global url
    if input_field.get() == 'https://www.': 
        popup1()
        return
    elif already_submitted == True: popup2()
    else:
        website_url = Label(output_frame, text='Site: ' + input_field.get())
        website_url.place(y=10, anchor=W)
        url = str(input_field.get())
    already_submitted = True
    

def selectButton(value, CLASSIFIERS):
    global already_selected
    global phisher
    if already_selected == True: popup2()
    elif already_submitted == False: 
        popup3()
        return
    else:
        selected_model = Label(output_frame, text='ML: ' + value)
        selected_model.place(y=30, anchor=W)
        phisher = joblib.load("C:/Users/saket/OneDrive/Desktop/Python Projects/Phishing Website/" + str(value) + ".joblib")
        progress_bar = Label(output_frame, text='Analyzing...')
        progress_bar.place(y=70, anchor=W)
        model_accuracy = str(next((accuracy_percentage for model_name, accuracy_percentage in CLASSIFIERS if model_name == value), None))
        final_accuracy = Label(output_frame, text='The Model Accuracy is: ' + model_accuracy)
        final_accuracy.place(y=90, anchor=W)
        displayFinalResult()
    already_selected = True


def displayFinalResult():
    global final_results
    show_safe_malicious = Label(output_frame, text='The Web-Address is: ' + final_results)
    show_safe_malicious.place(y=110, anchor=W)


def popup1():
    messagebox.showinfo('Error!', 'Please enter a URL.')


def popup2():
    messagebox.showinfo('Error!', 'This input field is already submitted.\nPlease restart the program to select a different field.')


def popup3():
    messagebox.showinfo('Error!', 'Please enter a website-URL first.')


# ***************************Logging related imports & settings**************************************

def getlogger(fileName = "newsScrapelog"): # format the log entries
    formatter = logging.Formatter('%(asctime)s %(name)s %(levelname)s %(message)s')

    my_path = os.path.abspath(os.path.dirname(__file__))
    if(not os.path.exists(os.path.join(my_path, "logs"))):
        os.makedirs(os.path.join(my_path, "logs"))

    logFilename = "logs/" + fileName
    handler = TimedRotatingFileHandler(os.path.join(my_path, logFilename),
                                    when="midnight",
                                    backupCount=5)
    handler.setFormatter(formatter)
    logger = logging.getLogger(__name__)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    return logger

# ***************************************************************************************************

input_frame = LabelFrame(root, text=' Enter Website URL here: ', width=250, padx=5, pady=5)
input_frame.pack(padx=15, pady=10)

input_field = Entry(input_frame, width=37, borderwidth=5)
input_field.pack()
input_field.insert(0, 'https://www.')

already_submitted = False
submit_button = Button(input_frame, text='Submit', padx=26, pady=2, command=submitButton) 
submit_button.pack(anchor=CENTER)
url = 'https://google.com/'

select_model_frame = LabelFrame(root, text=' Select Model to be used: ', width=250, padx=5, pady=5)
select_model_frame.pack(padx=15, pady=10)

CLASSIFIERS = [
	("Logistical Regression", '92.98%'),
	("Decision-Tree Classifier", '96.04%'),
	("Random-Forest Classifier", '97.21%'),
  ("Multi-layer Perceptron (MLP) Classifier", '94.68%'),
  ("AdaBoost Classifier", '93.58%'),
	("Gradient Boosting Classifier", '96.36%')
]

default_classifier = StringVar()
default_classifier.set(CLASSIFIERS[0][0])

for model_name, accuracy_percentage in CLASSIFIERS: Radiobutton(select_model_frame, text=model_name, variable=default_classifier, value=model_name).pack(anchor=W)

already_selected = False
phisher = joblib.load("C:/Users/saket/OneDrive/Desktop/Python Projects/Phishing Website/Logistical Regression.joblib")
select_button = Button(select_model_frame, text='Select', padx=30, pady=2, command=lambda: selectButton(default_classifier.get(), CLASSIFIERS)) 
select_button.pack(anchor=CENTER)

output_frame = LabelFrame(root, text=' Your Selections & Output: ', height=150, width=247, padx=5, pady=5)
output_frame.pack(padx=15, pady=10)

def mainFunction():
  site = [[]]
  for i in range(30): site[0].append(0)
  logger = getlogger("out")

  path_start = url.find(':') + 3
  path = url[path_start:]
  try:
      html = urlopen(url)
      bs = BeautifulSoup(html, 'html.parser')
  except:
      logger.info("Error opening page")
      bs = None

  try: domain = whois.query(path)
  except: domain = None
  logger.info(path)
  try:
      dnsresult = dns.resolver.query(path, 'A')
      for ipval in dnsresult: logger.info('IP:', ipval.to_text())
  except: dnsresult = None

  if(domain != None): logger.info(domain.__dict__)
  logger.info(dnsresult)

  # has IP:
  name = url.split("/")[2]
  count = 0
  parts = name.split(".")
  for string in parts:
    if(string.isnumeric()):
      count = count + 1
      if(count > 2): site[0][0] = -1
      else:
        site[0][0] = 1
        logger.info(site[0][0])

  # length of url
  if(len(url) > 60): site[0][1] = -1
  if(len(url) < 30): site[0][1] = 1

  # Shortening Service - Either check for 301 code or known names in url
  services = ["bit.ly", "is.gd", "t.co", "tinyurl.com", "tiny.cc"]
  site[0][1] = 1
  for service in services:
    if(service in url): site[0][1] = -1

  # having @ symbol
  if("@" in url): site[0][3] = -1
  else: site[0][3] = 1

  # having double slash
  if(path.find("//") == -1): site[0][4] = 1
  else: site[0][4] = -1

  # presence of -
  if(path.find("-") == -1): site[0][5] = 1
  else: site[0][5] = -1

  # having subdomain
  site[0][6] = -1

  # having https
  if(url[:5] == "https"): site[0][7] = 1
  else: site[0][7] = -1

  # domain registration length
  last_year_date = datetime.datetime.now() - relativedelta(years=1)
  if(domain != None and domain.creation_date > last_year_date): site[0][8] = -1
  else: site[0][8] = 1

  # favicon from diffrent url
  try:
      icons = favicon.get(url)
      logger.info(icons)
      if(icons != None and icons != [] and (path in icons[0].url or name in icons[0].url)): site[0][9] = 1
      else: site[0][9] = -1
  except: logger.info("Error opening url")

  # are all ports open
  site[0][10] = 0

  # is https-token in path
  if "https" in path: site[0][11] = -1
  else: site[0][11] = 1

  # images from same domain
  try:
      count = 0
      vcount = 0
      images = bs.find_all('img')
      for image in images:
          count = count + 1
          if(image['src'] != '' and image['src'] != None and (image['src'][0] == '/' or path in image['src'])):
              vcount = vcount + 1
              continue
      if(count != 0 and ((vcount / count) * 100 > 30)): site[0][12] = 1
      else: site[0][12] = -1
  except:
      logger.info("error opening images")
      site[0][12] = -1

  # url of anchor
  try:
      count = 0
      vcount = 0
      anchors = bs.find_all('a')
      for anchor in anchors:
          count = count + 1
          if(anchor['src'] != '' and anchor['src'] != None and (anchor['src'][0] == '/' or path in anchor['src'])):
              vcount = vcount + 1
              continue
      if(count != 0 and ((vcount / count) * 100 > 60)): site[0][13] = 1
      else: site[0][13] = -1
  except:
      logger.info("error ipening as")
      site[0][13] = -1

  # links in tags
  try:
      response = requests.get(url)
      soup = BeautifulSoup(response.text)
      metas = soup.find_all('meta')
      if(metas != None or metas != [] and(len(metas) > 5)): site[0][14] = 1
      else: site[0][14] = -1
  except:
      logger.info("error in getting meta")
      site[0][14] = -1

  # server form handler
  site[0][15] = -1

  # client-side submission to email using mailto
  site[0][16] = -1

  # check if whois exists
  try:
      if(domain != None): site[0][17] = 1
      else: site[0][17] = -1
  except:
      logger.info("No whois found")
      site[0][17] = -1

  # no of redirects
  try:
      r = requests.head(url)
      if(str(r.status_code)[0] == '2'): site[0][18] = -1
      else: site[0][18] = +1

  except Exception as e:
      logger.info(e)
      logger.info("Error finding redirects")

  # does onmouseover change statusbar
  site[0][19] = 0

  # is right click disabled
  site[0][20] = 0

  # popup window contains text forms
  site[0][21] = -1

  # iframe frameBorders
  site[0][22] = -1

  # no dns records
  if(dnsresult != None): site[0][25] = 1
  else: site[0][25] = -1

  # website traffic
  site[0][26] = -1

  # page rank value 
  site[0][27] = -1

  # in google index
  site[0][28] = -1

  # no of links pointing to them
  site[0][29] = -1

  # found in stastical reports
  results = ["Malicious", "Safe"]

  logger.info(site)
  final_results = results[int(phisher.predict(site))]

mainFunction()
root.mainloop()