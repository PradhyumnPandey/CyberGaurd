from flask import Flask, render_template, request
import joblib
import pandas as pd
import re
import os

app = Flask(__name__)

# Configuration
TRUSTED_DOMAINS = [
    # Payment & Loan Apps
    'mpkt.to', 'mpokket.com', 'mpokket',
    'paytm.com', 'phonepe.com', 'gpay.com', 'googlepay.com',
    'amazonpay.com', 'amazon.in', 'flipkart.com',
    
    # Banks
    'sbi.co.in', 'icicibank.com', 'hdfcbank.com', 'axisbank.com',
    'kotak.com', 'yesbank.in', 'pnbindia.in', 'canarabank.com',
    
    # Tech Companies
    'google.com', 'microsoft.com', 'github.com', 'linkedin.com',
    
    # E-commerce
    'amazon.com', 'flipkart.com', 'myntra.com',
    
    # Government
    'gov.in', 'nic.in', 'cybercrime.gov.in',
    
    # WhatsApp (only specific business domains)
    'whatsapp.com', 'wa.me'  # Added WhatsApp domains
]

# HIGH RISK KEYWORDS - These are major red flags
HIGH_RISK_KEYWORDS = [
    'bank details', 'share your bank', 'send money', 'transfer money',
    'otp', 'password', 'login details', 'credit card', 'debit card',
    'cvv', 'pin number', 'net banking', 'internet banking'
]

# Job/Prize/Lottery Scam Keywords
SCAM_KEYWORDS = [
    'won', 'winner', 'prize', 'lottery', 'jackpot', 'million',
    'billion', 'cash prize', 'reward', 'gift voucher', 'gift card',
    'congratulations', 'selected', 'interview', 'job offer', 'salary',
    'work from home', 'part time', 'easy money', 'quick money'
]

# Urgency keywords
URGENCY_KEYWORDS = [
    'urgent', 'immediately', 'now', 'today', 'expires', 'deadline',
    'limited time', 'hurry', 'quick', 'asap', 'action required'
]

# Suspicious phone number patterns
SUSPICIOUS_PHONE_PATTERNS = [
    r'wa\.me',  # WhatsApp links
    r'whatsapp\.com',
    r'telegram\.me',
    r'\b[6-9]\d{9}\b'  # Indian mobile numbers
]

# Load the trained model
print("📦 Loading AI Model...")
try:
    model = joblib.load('phishing_model.pkl')
    feature_cols = joblib.load('feature_columns.pkl')
    print("✅ Model loaded successfully!")
    print(f"📊 Features loaded: {len(feature_cols)}")
except Exception as e:
    print(f"❌ Error loading model: {e}")
    model = None
    feature_cols = None

def is_suspicious_phone(text):
    """Detect suspicious phone numbers and messaging app links"""
    text_lower = text.lower()
    for pattern in SUSPICIOUS_PHONE_PATTERNS:
        if re.search(pattern, text_lower):
            return True
    return False

def extract_features(message):
    """Extract ALL features needed for detection"""
    features = {}
    text_lower = message.lower()
    
    # 1. URL Detection
    url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    urls = re.findall(url_pattern, text_lower)
    features['has_url'] = 1 if urls else 0
    features['url_count'] = len(urls)
    
    # 2. WhatsApp/Messaging App Detection
    features['has_whatsapp'] = 1 if 'wa.me' in text_lower or 'whatsapp.com' in text_lower else 0
    
    # 3. Trusted Domain Check
    features['trusted_domain'] = 0
    if features['has_url']:
        for domain in TRUSTED_DOMAINS:
            if domain in text_lower:
                # Special case: wa.me is ONLY trusted if it's from known business
                if domain == 'wa.me' or domain == 'whatsapp.com':
                    # Check if it's from a known business pattern
                    if any(biz in text_lower for biz in ['official', 'verified', 'support']):
                        features['trusted_domain'] = 1
                    else:
                        features['trusted_domain'] = 0  # Untrusted WhatsApp link
                else:
                    features['trusted_domain'] = 1
                break
    
    # 4. HIGH RISK KEYWORDS (bank details, etc.)
    high_risk_count = 0
    for phrase in HIGH_RISK_KEYWORDS:
        if phrase in text_lower:
            high_risk_count += 1
    features['high_risk_count'] = high_risk_count
    
    # 5. SCAM KEYWORDS (job offers, prizes, etc.)
    scam_count = 0
    for word in SCAM_KEYWORDS:
        if word in text_lower:
            scam_count += 1
    features['scam_count'] = scam_count
    
    # 6. URGENCY KEYWORDS
    urgency_count = 0
    for word in URGENCY_KEYWORDS:
        if word in text_lower:
            urgency_count += 1
    features['urgency_count'] = urgency_count
    
    # 7. Phone Number Detection
    features['has_phone'] = 1 if is_suspicious_phone(text_lower) else 0
    
    # 8. Request for sensitive info
    sensitive_phrases = ['share your', 'send your', 'provide your', 'give your', 'contact']
    features['requests_info'] = 1 if any(phrase in text_lower for phrase in sensitive_phrases) else 0
    
    # 9. Numbers in message
    features['has_number'] = 1 if any(char.isdigit() for char in message) else 0
    features['number_count'] = sum(c.isdigit() for c in message)
    
    # 10. Salary/Money mentions
    features['has_money'] = 1 if any(word in text_lower for word in ['salary', 'rs', 'rupees', '₹', '$']) else 0
    
    # 11. Text Statistics
    words = message.split()
    features['word_count'] = len(words)
    features['char_count'] = len(message)
    features['avg_word_length'] = sum(len(w) for w in words) / max(len(words), 1)
    
    # 12. Special Characters
    features['exclamation_count'] = message.count('!')
    features['question_count'] = message.count('?')
    
    # 13. Capitalization
    caps_words = sum(1 for word in words if word.isupper() and len(word) > 2)
    features['caps_count'] = caps_words
    features['caps_ratio'] = caps_words / max(len(words), 1)
    
    # 14. Suspicious count (for model compatibility)
    suspicious_words = ['verify', 'account', 'suspend', 'click', 'login', 'bank', 'password', 'security', 'update', 'claim']
    suspicious_count = 0
    for word in suspicious_words:
        if word in text_lower:
            suspicious_count += 1
    features['suspicious_count'] = suspicious_count
    
    return features

def get_detailed_reasons(features, message):
    """Generate human-readable reasons for the prediction"""
    reasons = []
    text_lower = message.lower()
    
    # HIGH PRIORITY SCAM DETECTION
    
    # Job Scam Detection
    if 'congratulations' in text_lower and any(word in text_lower for word in ['interview', 'job', 'salary']):
        reasons.append("⚠️ SCAM: Fake job offer - congratulations with interview")
    
    if 'salary' in text_lower and 'contact' in text_lower:
        reasons.append("⚠️ SCAM: Job offer asking to contact on personal number")
    
    if features['scam_count'] >= 2:
        reasons.append(f"⚠️ Multiple scam indicators ({features['scam_count']} scam keywords)")
    
    # WhatsApp Scam Detection
    if features['has_whatsapp'] and features['trusted_domain'] == 0:
        reasons.append("⚠️ SCAM: Untrusted WhatsApp link - common in job scams")
    
    if 'wa.me' in text_lower and any(word in text_lower for word in ['job', 'salary', 'congratulations']):
        reasons.append("⚠️ CRITICAL: Job scam using WhatsApp link")
    
    # Prize/Job combo
    if features['scam_count'] > 0 and features['has_phone']:
        reasons.append("⚠️ Scam keywords combined with contact number")
    
    if features['has_money'] and features['has_phone'] and not features['trusted_domain']:
        reasons.append("⚠️ Money offer with contact number - potential scam")
    
    # Bank/Financial scams
    if features['high_risk_count'] > 0:
        reasons.append("⚠️ CRITICAL: Asking for bank details or sensitive information")
    
    # URL Analysis
    if features['has_url']:
        if features['trusted_domain']:
            reasons.append("Contains link from trusted company")
        else:
            reasons.append("⚠️ Contains unknown/untrusted URL")
    
    # Suspicious patterns
    if 'bank details' in text_lower:
        reasons.append("⚠️ Direct request for bank details")
    
    if 'share your' in text_lower and any(word in text_lower for word in ['bank', 'account', 'card']):
        reasons.append("⚠️ Asking you to share financial information")
    
    if 'won' in text_lower and 'money' in text_lower:
        reasons.append("⚠️ 'Won money' scam pattern detected")
    
    # Urgency
    if features['urgency_count'] > 0:
        reasons.append(f"Creates urgency with {features['urgency_count']} urgency word(s)")
    
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
        
        # ===== INTELLIGENT SCAM DETECTION RULES =====
        
        # HIGH PRIORITY RULES - These ALWAYS trigger phishing warning
        
        # Rule 1: Job Scam Pattern (Congratulations + Interview + WhatsApp)
        if 'congratulations' in message.lower() and 'interview' in message.lower() and 'wa.me' in message.lower():
            reasons = [
                "⚠️ CRITICAL: Fake job offer scam detected",
                "⚠️ Pattern: 'Congratulations for interview' + WhatsApp link",
                "⚠️ Scammers use fake jobs to collect personal details",
                "✅ Real companies NEVER ask to contact on personal WhatsApp"
            ]
            return render_template('index.html',
                                 result="⚠️ PHISHING DETECTED",
                                 result_class="phishing",
                                 confidence="99.9%",
                                 reasons=reasons,
                                 message=message)
        
        # Rule 2: WhatsApp link with job/salary mentions
        if 'wa.me' in message.lower() and any(word in message.lower() for word in ['job', 'salary', 'interview', 'work']):
            reasons = [
                "⚠️ SCAM: Job offer via WhatsApp link",
                "⚠️ Legitimate companies use email, not personal WhatsApp",
                "⚠️ Common recruitment scam pattern"
            ]
            return render_template('index.html',
                                 result="⚠️ PHISHING DETECTED",
                                 result_class="phishing",
                                 confidence="99.5%",
                                 reasons=reasons,
                                 message=message)
        
        # Rule 3: High scam keyword count
        if features['scam_count'] >= 3:
            reasons = get_detailed_reasons(features, message)
            return render_template('index.html',
                                 result="⚠️ PHISHING DETECTED",
                                 result_class="phishing",
                                 confidence="99.0%",
                                 reasons=reasons,
                                 message=message)
        
        # Rule 4: Asking for bank details
        if features['high_risk_count'] > 0:
            reasons = get_detailed_reasons(features, message)
            return render_template('index.html',
                                 result="⚠️ PHISHING DETECTED",
                                 result_class="phishing",
                                 confidence="99.9%",
                                 reasons=reasons,
                                 message=message)
        
        # Rule 5: Prize claims with contact info
        if features['scam_count'] > 0 and features['has_phone']:
            reasons = get_detailed_reasons(features, message)
            return render_template('index.html',
                                 result="⚠️ PHISHING DETECTED",
                                 result_class="phishing",
                                 confidence="98.0%",
                                 reasons=reasons,
                                 message=message)
        
        # Rule 6: Trusted Domain - Safe
        if features['trusted_domain'] == 1:
            reasons = get_detailed_reasons(features, message)
            return render_template('index.html',
                                 result="✅ SAFE MESSAGE",
                                 result_class="safe",
                                 confidence="99.9%",
                                 reasons=reasons,
                                 message=message)
        
        # ===== USE THE TRAINED MODEL FOR PREDICTION =====
        if model is not None and feature_cols is not None:
            try:
                # Prepare features for model
                features_df = pd.DataFrame([features])
                
                # Ensure all required columns exist
                for col in feature_cols:
                    if col not in features_df.columns:
                        features_df[col] = 0
                features_df = features_df[feature_cols]
                
                # Make prediction with the trained model
                prediction = model.predict(features_df)[0]
                probability = model.predict_proba(features_df)[0]
                
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
                print(f"Model prediction error: {e}")
                # Fall through to rule-based if model fails
        
        # ===== FALLBACK TO RULE-BASED DETECTION =====
        # Calculate risk score
        risk_score = 0
        risk_score += features['scam_count'] * 25
        risk_score += features['high_risk_count'] * 50
        risk_score += features['has_phone'] * 20
        risk_score += features['has_whatsapp'] * 30
        risk_score += features['urgency_count'] * 10
        risk_score += features['has_url'] * 15
        risk_score += features['has_money'] * 15
        
        if risk_score > 30:
            result = "⚠️ PHISHING DETECTED"
            confidence = min(risk_score, 99)
            result_class = "phishing"
        else:
            result = "✅ SAFE MESSAGE"
            confidence = 100 - min(risk_score, 50)
            result_class = "safe"
        
        reasons = get_detailed_reasons(features, message)
        
        return render_template('index.html',
                             result=result,
                             result_class=result_class,
                             confidence=f"{confidence:.1f}%",
                             reasons=reasons,
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
    print("📡 Server starting...")
    print("="*60)
    print(f"✅ Model loaded: {'Yes' if model else 'No'}")
    print(f"✅ Features: {len(feature_cols) if feature_cols else 0}")
    print("="*60 + "\n")
    
    # Get port from environment variable (for Render) or use 10000 as default
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)