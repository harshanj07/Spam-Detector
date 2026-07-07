#!/usr/bin/env python
# coding: utf-8

# In[26]:


import pickle
import string
import nltk
from sklearn.feature_extraction.text import CountVectorizer,TfidfVectorizer
from nltk.corpus import stopwords
from nltk.stem.porter import PorterStemmer
ps = PorterStemmer()
import streamlit as st
nltk.download('punkt')
nltk.download('stopwords')

# In[21]:


t = pickle.load(open('vectorizer.pkl','rb'))
m = pickle.load(open('model.pkl','rb'))


# In[22]:


def transform_text(text):
#     lowecase
    text = text.lower()
#     tokenization
    text = nltk.word_tokenize(text)
    
    y = []
    
#     removing spl char
    for i in text:
        if i.isalnum():
            y.append(i)
    
    text = y[:]
    y.clear()
    
#     removing punctuation , frequent stopwords
    for i in text:
        if i not in stopwords.words('english') and i not in string.punctuation:
            y.append(i)
            
    text = y[:]
    y.clear()
    
#     stemming (eating->eat)
    for i in text:
        y.append(ps.stem(i))
    
    return " ".join(y)


# In[34]:
try:
    str1 = st.text_area("Message : ")

# def predict(str1):
#     	str1 = transform_text(str1)
        
#     	vec_input = t.transform([str1])
#     	# print(str1)
#     	result = list(m.predict(vec_input))

    def predict(s):
        str1 = transform_text(s)

        vec_input = t.transform([s])

        result = list(m.predict(vec_input))

        if(result[0]==1):
            st.write("spam")
        else:
            st.write("ham")


    if(st.button("Predict")):
        predict(str1)

except ValueError:
    st.write("")

    


# In[ ]:




