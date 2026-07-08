#!/usr/bin/env python
# coding: utf-8

import pickle
import string
import nltk
import re
import streamlit as st
from nltk.corpus import stopwords
from nltk.stem.porter import PorterStemmer

# Set page config as the first Streamlit command
st.set_page_config(
    page_title="AI Spam & Scam Detector Pro",
    page_icon="🛡️",
    layout="centered",
    initial_sidebar_state="collapsed"
)

# Initialize models and stemmer
ps = PorterStemmer()

# Download NLTK resources silently
nltk.download('punkt', quiet=True)
nltk.download('stopwords', quiet=True)

# Load pickles
t = pickle.load(open('vectorizer.pkl', 'rb'))
m = pickle.load(open('model.pkl', 'rb'))

def transform_text(text):
    # lowercase
    text = text.lower()
    # tokenization
    text = nltk.word_tokenize(text)
    
    y = []
    # removing spl char
    for i in text:
        if i.isalnum():
            y.append(i)
    
    text = y[:]
    y.clear()
    
    # removing punctuation, frequent stopwords
    for i in text:
        if i not in stopwords.words('english') and i not in string.punctuation:
            y.append(i)
            
    text = y[:]
    y.clear()
    
    # stemming
    for i in text:
        y.append(ps.stem(i))
    
    return " ".join(y)

# Link Safety Heuristics Check
def check_links(text):
    url_pattern = re.compile(r'https?://[^\s()<>]+|www\.[^\s()<>]+')
    urls = url_pattern.findall(text)
    
    if not urls:
        return []
        
    results = []
    suspicious_keywords = {'win', 'free', 'prize', 'gift', 'claim', 'login', 'verify', 'update', 'banking', 'secure', 'bonus', 'cash', 'reward', 'offer'}
    suspicious_tlds = {'.xyz', '.click', '.win', '.top', '.club', '.online', '.loan', '.support', '.download', '.info', '.biz'}
    
    for url in urls:
        is_suspicious = False
        reasons = []
        
        # 1. HTTP check
        if url.startswith('http://'):
            is_suspicious = True
            reasons.append("Unsecured protocol (HTTP)")
            
        # Domain extraction
        domain = url.lower()
        if '://' in domain:
            domain = domain.split('://')[1]
        domain = domain.split('/')[0]
        
        # 2. Suspicious TLD check
        for tld in suspicious_tlds:
            if domain.endswith(tld):
                is_suspicious = True
                reasons.append(f"Suspicious domain extension ({tld})")
                break
                
        # 3. Suspicious keywords check
        url_lower = url.lower()
        matched_kw = [kw for kw in suspicious_keywords if kw in url_lower]
        if matched_kw:
            is_suspicious = True
            reasons.append(f"Contains promotional/scam keywords ({', '.join(matched_kw)})")
            
        # 4. Raw IP Check
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        if ip_pattern.match(domain):
            is_suspicious = True
            reasons.append("Uses raw IP address instead of domain name")
            
        # 5. Missing TLD / Dot check (excluding localhost)
        if '.' not in domain and domain != 'localhost':
            is_suspicious = True
            reasons.append("Invalid or missing domain extension (TLD)")
            
        results.append({
            'url': url,
            'is_suspicious': is_suspicious,
            'reasons': reasons
        })
        
    return results

# Urgency Analysis Heuristics Check
def check_urgency(text, has_suspicious_links=False):
    urgency_keywords = {
        'urgent', 'immediately', 'now', 'hurry', 'expire', 'limited', 'action', 
        'required', 'deadline', 'soon', 'instant', 'cash', 'alert', 'warn',
        'win', 'won', 'congratulations', 'congratulation', 'prize', 'claim', 'free', 'offer',
        'click', 'clickhere'
    }
    
    words = nltk.word_tokenize(text.lower())
    
    # 1. Keyword score (max 50)
    matched_words = [w for w in words if w in urgency_keywords]
    keyword_score = min(len(matched_words) * 20, 50)
    
    # 2. Capitalization score (max 30)
    caps_words = []
    for w in text.split():
        clean_w = re.sub(r'[^a-zA-Z]', '', w)
        if clean_w.isupper() and len(clean_w) >= 3:
            caps_words.append(clean_w)
    caps_score = min(len(caps_words) * 15, 30)
    
    # 3. Exclamation mark score (max 20)
    excl_count = text.count('!')
    excl_score = min(excl_count * 10, 20)
    
    # 4. Suspicious Link penalty boost
    link_boost = 30 if has_suspicious_links else 0
    
    total_score = min(keyword_score + caps_score + excl_score + link_boost, 100)
    
    level = "Low"
    if total_score >= 50:
        level = "High"
    elif total_score >= 25:
        level = "Medium"
        
    return {
        'score': total_score,
        'level': level,
        'matched_words': list(set(matched_words)),
        'caps_words': caps_words,
        'excl_count': excl_count,
        'link_boost': link_boost
    }

# --- UI Header ---
st.markdown("<h1 style='text-align: center; color: #1E3A8A; font-family: sans-serif; margin-top: -30px;'>🛡️ AI Spam & Link Analyzer</h1>", unsafe_allow_html=True)
st.markdown("<p style='text-align: center; color: #4B5563; font-size: 1.1rem; margin-bottom: 25px;'>Analyze text messages for spam, scan link safety, and detect urgency/sentiment patterns.</p>", unsafe_allow_html=True)

# Input container
str1 = st.text_area("Enter your message to analyze:", height=130, placeholder="Paste your email, SMS, or suspicious message here...")

# Predict button
if st.button("🔍 Analyze Message", use_container_width=True):
    if str1.strip() == "":
        st.warning("⚠️ Please enter a message to analyze.")
    else:
        # Preprocessing & classification
        str1_transformed = transform_text(str1)
        vec_input = t.transform([str1_transformed])
        prediction = m.predict(vec_input)[0]
        probabilities = m.predict_proba(vec_input)[0]
        
        # Link Analysis
        link_results = check_links(str1)
        
        # Check if there is any suspicious link
        has_suspicious_links = any(res['is_suspicious'] for res in link_results)
        
        # Urgency Analysis
        urgency_results = check_urgency(str1, has_suspicious_links=has_suspicious_links)
        
        
        st.markdown("---")
        
        # Two-column layout
        col1, col2 = st.columns([1.1, 0.9])
        
        with col1:
            st.markdown("### 📊 Classification Result")
            if prediction == 1:
                confidence = probabilities[1] * 100
                st.markdown(f"""
                <div style="background-color: rgba(239, 68, 68, 0.15); border: 2px solid #EF4444; border-radius: 12px; padding: 20px; text-align: center; margin-bottom: 20px;">
                    <h2 style="color: #EF4444; margin: 0; font-size: 1.8rem; font-family: sans-serif;">⚠️ SPAM DETECTED</h2>
                    <p style="color: #B91C1C; margin: 5px 0 0 0; font-weight: 500; font-size: 1.1rem;">Confidence Score: {confidence:.1f}%</p>
                </div>
                """, unsafe_allow_html=True)
                st.progress(probabilities[1])
            else:
                confidence = probabilities[0] * 100
                st.markdown(f"""
                <div style="background-color: rgba(16, 185, 129, 0.15); border: 2px solid #10B981; border-radius: 12px; padding: 20px; text-align: center; margin-bottom: 20px;">
                    <h2 style="color: #10B981; margin: 0; font-size: 1.8rem; font-family: sans-serif;">✅ HAM (SAFE)</h2>
                    <p style="color: #047857; margin: 5px 0 0 0; font-weight: 500; font-size: 1.1rem;">Confidence Score: {confidence:.1f}%</p>
                </div>
                """, unsafe_allow_html=True)
                st.progress(probabilities[0])
            
            # URL safety
            st.markdown("### 🔗 URL Safety Scanner")
            if not link_results:
                st.info("ℹ️ No links detected in the message.")
            else:
                for res in link_results:
                    if res['is_suspicious']:
                        st.markdown(f"""
                        <div style="background-color: rgba(220, 38, 38, 0.1); border-left: 4px solid #DC2626; padding: 10px; border-radius: 4px; margin-bottom: 10px;">
                            <strong style="color: #DC2626;">Suspicious Link:</strong> <code style="word-break: break-all;">{res['url']}</code>
                        </div>
                        """, unsafe_allow_html=True)
                        for r in res['reasons']:
                            st.markdown(f"<span style='color: #DC2626; font-size: 0.9rem;'>&nbsp;&nbsp;❌ {r}</span>", unsafe_allow_html=True)
                    else:
                        st.markdown(f"""
                        <div style="background-color: rgba(5, 150, 105, 0.1); border-left: 4px solid #059669; padding: 10px; border-radius: 4px; margin-bottom: 10px;">
                            <strong style="color: #059669;">Appears Safe:</strong> <code style="word-break: break-all;">{res['url']}</code>
                            <br><span style='color: #047857; font-size: 0.85rem;'>✓ Secure HTTPS and clean domain name.</span>
                        </div>
                        """, unsafe_allow_html=True)
        
        with col2:
            # Urgency Metric
            st.markdown("### ⚡ Urgency Indicator")
            u_lvl = urgency_results['level']
            u_score = urgency_results['score']
            
            if u_lvl == "High":
                st.markdown(f"""
                <div style="background-color: rgba(217, 119, 6, 0.15); border-left: 5px solid #D97706; padding: 15px; border-radius: 6px; margin-bottom: 20px;">
                    <h4 style="color: #D97706; margin: 0; font-family: sans-serif;">High Urgency Detected ({u_score}/100)</h4>
                    <p style="margin: 5px 0 0 0; font-size: 0.9rem; color: #78350F;">Creates artificial pressure (capitalization, exclamation marks, or urgent words).</p>
                </div>
                """, unsafe_allow_html=True)
            elif u_lvl == "Medium":
                st.markdown(f"""
                <div style="background-color: rgba(37, 99, 235, 0.15); border-left: 5px solid #2563EB; padding: 15px; border-radius: 6px; margin-bottom: 20px;">
                    <h4 style="color: #2563EB; margin: 0; font-family: sans-serif;">Medium Urgency Detected ({u_score}/100)</h4>
                    <p style="margin: 5px 0 0 0; font-size: 0.9rem; color: #1E3A8A;">Contains some time-sensitive or highly emphasized words.</p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div style="background-color: rgba(75, 85, 99, 0.1); border-left: 5px solid #4B5563; padding: 15px; border-radius: 6px; margin-bottom: 20px;">
                    <h4 style="color: #4B5563; margin: 0; font-family: sans-serif;">Low Urgency ({u_score}/100)</h4>
                    <p style="margin: 5px 0 0 0; font-size: 0.9rem; color: #374151;">Normal natural tone with no pressure elements detected.</p>
                </div>
                """, unsafe_allow_html=True)
                

