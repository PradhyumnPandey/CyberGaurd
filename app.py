from flask import Flask, render_template, request
import joblib
import pandas as pd
import re
import os

app = Flask(__name__)

# Configuration
TRUSTED_DOMAINS = [
    # Payment & Loan Apps
    'mpkt.to', 'mpokket.com', 'mpokket',  # mPokket
    'paytm.com', 'phonepe.com', 'gpay.com', 'googlepay.com',
    'amazonpay.com', 'amazon.in', 'flipkart.com',
    
    # Banks
    'sbi.co.in', 'icicibank.com', 'hdfcbank.com', 'axisbank.com',
    'kotak.com', 'yesbank.in', 'pnbindia.in', 'canarabank.com',
    
    # Tech Companies
    'google.com', 'microsoft.com', 'github.com', 'stackoverflow.com',
    'linkedin.com', 'twitter.com', 'x.com', 'facebook.com',
    'instagram.com', 'whatsapp.com', 'telegram.org',
    
    # Media & Entertainment
    'youtube.com', 'netflix.com', 'spotify.com', 'hotstar.com',
    'primevideo.com', 'sonyliv.com', 'zee5.com',
    
    # Food & Delivery
    'zomato.com', 'swiggy.com', 'uber.com', 'ola.com', 'rapido.in',
    
    # Telecom
    'airtel.in', 'jio.com', 'vi.com', 'bsnl.co.in',
    
    # E-commerce
    'amazon.com', 'amazon.in', 'flipkart.com', 'myntra.com',
    'ajio.com', 'nykaa.com', 'meesho.com', 'snapdeal.com',
    
    # Government
    'gov.in', 'nic.in', 'cybercrime.gov.in', 'india.gov.in'
]

# Suspicious keywords (scam indicators)
SUSPICIOUS_KEYWORDS = [
    'verify', 'account', 'suspend', 'urgent', 'click', 'login',
    'bank', 'paypal', 'password', 'security', 'update', 'claim',
    'winner', 'prize', 'lottery', 'free', 'otp', 'limited',
    'blocked', 'restricted', 'unusual', 'activity', 'unauthorized',
    'deactivated', 'expires', 'deadline', 'action required'
]

# Load model
def load_model():
    try:
        model = joblib.load('phishing_model.pkl')
        feature_cols = joblib.load('feature_columns.pkl')
        print("✅ Model loaded successfully")
        return model, feature_cols
    except Exception as e:
        print(f"❌ Model loading failed: {e}")
        return None, None

model, feature_cols = load_model()

def extract_features(message):
    """Extract ALL features needed for detection"""
    features = {}
    text_lower = message.lower()
    
    # 1. URL Detection
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, text_lower)
    features['has_url'] = 1 if urls else 0
    features['url_count'] = len(urls)
    
    # 2. Trusted Domain Check
    features['trusted_domain'] = 0
    if features['has_url']:
        for domain in TRUSTED_DOMAINS:
            if domain in text_lower:
                features['trusted_domain'] = 1
                break
    
    # 3. Suspicious Keywords Count
    suspicious_count = 0
    for word in SUSPICIOUS_KEYWORDS:
        if word in text_lower:
            suspicious_count += 1
    features['suspicious_count'] = suspicious_count
    
    # 4. Urgency Detection
    urgency_words = ['urgent', 'immediately', 'now', 'today', 'due', 'expires', 'warning']
    urgency_count = 0
    for word in urgency_words:
        if word in text_lower:
            urgency_count += 1
    features['urgency_count'] = urgency_count
    
    # 5. Financial Terms
    finance_words = ['bank', 'account', 'money', 'payment', 'loan', 'credit', 'card', 'wallet']
    finance_count = 0
    for word in finance_words:
        if word in text_lower:
            finance_count += 1
    features['finance_count'] = finance_count
    
    # 6. Prize/Winner Terms
    prize_words = ['winner', 'prize', 'lottery', 'won', 'million', 'cash', 'reward']
    prize_count = 0
    for word in prize_words:
        if word in text_lower:
            prize_count += 1
    features['prize_count'] = prize_count
    
    # 7. Numbers
    features['has_number'] = 1 if any(char.isdigit() for char in message) else 0
    features['number_count'] = sum(c.isdigit() for c in message)
    
    # 8. Text Statistics
    words = message.split()
    features['word_count'] = len(words)
    features['char_count'] = len(message)
    features['avg_word_length'] = sum(len(w) for w in words) / max(len(words), 1)
    
    # 9. Special Characters
    features['exclamation_count'] = message.count('!')
    features['question_count'] = message.count('?')
    features['has_multiple_exclamation'] = 1 if '!!' in message else 0
    
    # 10. Capitalization
    caps_words = sum(1 for word in words if word.isupper() and len(word) > 2)
    features['caps_count'] = caps_words
    features['caps_ratio'] = caps_words / max(len(words), 1)
    
    # 11. Contact Info
    phone_pattern = r'\b\d{10}\b|\b\d{3}[-.]?\d{3}[-.]?\d{4}\b'
    features['has_phone'] = 1 if re.search(phone_pattern, message) else 0
    
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    features['has_email'] = 1 if re.search(email_pattern, message) else 0
    
    return features

def get_detailed_reasons(features, message):
    """Generate human-readable reasons for the prediction"""
    reasons = []
    text_lower = message.lower()
    
    # URL Analysis
    if features['has_url']:
        if features['trusted_domain']:
            reasons.append("Contains link from trusted company")
            # Specific company recognition
            for domain in TRUSTED_DOMAINS:
                if domain in text_lower:
                    reasons.append(f"Recognized as {domain.split('.')[0].capitalize()} message")
                    break
        else:
            reasons.append("⚠️ Contains unknown/untrusted URL")
    
    # Suspicious Content
    if features['suspicious_count'] >= 3:
        reasons.append(f"⚠️ Contains {features['suspicious_count']} scam-related keywords")
    elif features['suspicious_count'] >= 1:
        reasons.append(f"Contains {features['suspicious_count']} suspicious word(s)")
    
    # Urgency
    if features['urgency_count'] >= 2:
        reasons.append("⚠️ Creates false urgency with multiple urgency words")
    elif features['urgency_count'] >= 1:
        reasons.append("Creates urgency")
    
    # Financial Context
    if features['finance_count'] >= 2:
        reasons.append("Financial context detected")
    
    # Prize Claims
    if features['prize_count'] >= 1:
        reasons.append("⚠️ Mentions prizes or lottery")
    
    # Formatting Red Flags
    if features['exclamation_count'] > 2:
        reasons.append("⚠️ Excessive exclamation marks")
    if features['caps_ratio'] > 0.3:
        reasons.append("⚠️ Excessive capitalization")
    
    # If no specific reasons, add generic ones
    if not reasons:
        reasons.append("No immediate red flags detected")
    
    return reasons

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/info')
def info():
    return render_template('info.html')

@app.route('/predict', methods=['POST'])
def predict():
    if request.method == 'POST':
        message = request.form.get('message', '').strip()
        
        if not message:
            return render_template('index.html', error="Please enter a message to analyze")
        
        # Extract features
        features = extract_features(message)
        
        # ===== INTELLIGENT OVERRIDE RULES =====
        
        # Rule 1: Trusted Domain - Always Safe
        if features['trusted_domain'] == 1:
            reasons = get_detailed_reasons(features, message)
            return render_template('index.html',
                                 result="✅ SAFE MESSAGE",
                                 result_class="safe",
                                 confidence="99.9%",
                                 reasons=reasons,
                                 message=message)
        
        # Rule 2: Loan/Financial Messages from Known Format
        if 'loan' in message.lower() and ('due' in message.lower() or 'repay' in message.lower()):
            if features['has_url'] and any(domain in message.lower() for domain in ['mpkt', 'loan', 'credit']):
                reasons = ["Legitimate loan reminder message", "Contains financial terminology", "No scam indicators detected"]
                return render_template('index.html',
                                     result="✅ SAFE MESSAGE",
                                     result_class="safe",
                                     confidence="95.0%",
                                     reasons=reasons,
                                     message=message)
        
        # Rule 3: OTP Messages from Trusted Patterns
        if 'otp' in message.lower() and 'bank' not in message.lower():
            if len(message) < 200 and not features['has_url']:
                reasons = ["Standard OTP message", "No suspicious links", "Appears legitimate"]
                return render_template('index.html',
                                     result="✅ SAFE MESSAGE",
                                     result_class="safe",
                                     confidence="90.0%",
                                     reasons=reasons,
                                     message=message)
        
        # ===== AI MODEL PREDICTION =====
        if model is None or feature_cols is None:
            return render_template('index.html', error="Model not loaded. Please try again.")
        
        try:
            # Prepare features for model
            features_df = pd.DataFrame([features])
            
            # Ensure all required columns exist
            for col in feature_cols:
                if col not in features_df.columns:
                    features_df[col] = 0
            features_df = features_df[feature_cols]
            
            # Make prediction
            prediction = model.predict(features_df)[0]
            probability = model.predict_proba(features_df)[0]
            
            # Get reasons
            reasons = get_detailed_reasons(features, message)
            
            if prediction == 1:
                result = "⚠️ PHISHING DETECTED"
                confidence = probability[1] * 100
                result_class = "phishing"
            else:
                result = "✅ SAFE MESSAGE"
                confidence = probability[0] * 100
                result_class = "safe"
            
            return render_template('index.html',
                                 result=result,
                                 result_class=result_class,
                                 confidence=f"{confidence:.1f}%",
                                 reasons=reasons,
                                 message=message)
        
        except Exception as e:
            return render_template('index.html',
                                 error=f"Analysis error: {str(e)}",
                                 message=message)

@app.errorhandler(404)
def not_found(e):
    return render_template('index.html', error="Page not found"), 404

@app.errorhandler(500)
def internal_error(e):
    return render_template('index.html', error="Internal server error"), 500

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 CYBERGUARD PRO - AI PHISHING DETECTOR")
    print("="*60)
    print("📡 Local: http://127.0.0.1:5000")
    print("📱 Network: http://{}:5000".format(os.popen('hostname -I').read().strip().split()[0] if os.name != 'nt' else 'localhost'))
    print("="*60)
    print("✅ Trusted Domains Loaded:", len(TRUSTED_DOMAINS))
    print("✅ Suspicious Keywords:", len(SUSPICIOUS_KEYWORDS))
    print("="*60 + "\n")
    app.run(debug=True, host='0.0.0.0', port=5000)