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
    'gov.in', 'nic.in', 'cybercrime.gov.in'
]

# Suspicious keywords (HIGH priority - these are major red flags)
HIGH_RISK_KEYWORDS = [
    'bank details', 'share your bank', 'send money', 'transfer money',
    'otp', 'password', 'login details', 'credit card', 'debit card',
    'cvv', 'pin number', 'net banking', 'internet banking'
]

# Prize/Lottery keywords
PRIZE_KEYWORDS = [
    'won', 'winner', 'prize', 'lottery', 'jackpot', 'million',
    'billion', 'cash prize', 'reward', 'gift voucher', 'gift card'
]

# Urgency keywords
URGENCY_KEYWORDS = [
    'urgent', 'immediately', 'now', 'today', 'expires', 'deadline',
    'limited time', 'hurry', 'quick', 'asap', 'action required'
]

# Suspicious phone number patterns (Indian numbers)
def is_suspicious_phone(text):
    # Look for 10-digit numbers (Indian mobile)
    phone_pattern = r'\b[6-9]\d{9}\b'
    phones = re.findall(phone_pattern, text)
    if phones:
        # If phone number is present WITHOUT trusted context, it's suspicious
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
    
    # 2. Trusted Domain Check
    features['trusted_domain'] = 0
    if features['has_url']:
        for domain in TRUSTED_DOMAINS:
            if domain in text_lower:
                features['trusted_domain'] = 1
                break
    
    # 3. HIGH RISK KEYWORDS (bank details, etc.)
    high_risk_count = 0
    for phrase in HIGH_RISK_KEYWORDS:
        if phrase in text_lower:
            high_risk_count += 1
    features['high_risk_count'] = high_risk_count
    
    # 4. PRIZE KEYWORDS (won, lottery, etc.)
    prize_count = 0
    for word in PRIZE_KEYWORDS:
        if word in text_lower:
            prize_count += 1
    features['prize_count'] = prize_count
    
    # 5. URGENCY KEYWORDS
    urgency_count = 0
    for word in URGENCY_KEYWORDS:
        if word in text_lower:
            urgency_count += 1
    features['urgency_count'] = urgency_count
    
    # 6. Phone Number Detection
    features['has_phone'] = 1 if is_suspicious_phone(text_lower) else 0
    
    # 7. Request for sensitive info
    sensitive_phrases = ['share your', 'send your', 'provide your', 'give your']
    features['requests_info'] = 1 if any(phrase in text_lower for phrase in sensitive_phrases) else 0
    
    # 8. Numbers in message
    features['has_number'] = 1 if any(char.isdigit() for char in message) else 0
    features['number_count'] = sum(c.isdigit() for c in message)
    
    # 9. Text Statistics
    words = message.split()
    features['word_count'] = len(words)
    features['char_count'] = len(message)
    
    # 10. Special Characters
    features['exclamation_count'] = message.count('!')
    features['question_count'] = message.count('?')
    
    # 11. Capitalization
    caps_words = sum(1 for word in words if word.isupper() and len(word) > 2)
    features['caps_count'] = caps_words
    
    return features

def get_detailed_reasons(features, message):
    """Generate human-readable reasons for the prediction"""
    reasons = []
    text_lower = message.lower()
    
    # HIGH PRIORITY - These ALWAYS indicate phishing
    if features['high_risk_count'] > 0:
        reasons.append("⚠️ CRITICAL: Asking for bank details or sensitive information")
    
    if features['prize_count'] > 0:
        reasons.append("⚠️ Prize/Lottery claim - common scam tactic")
    
    if features['has_phone'] and features['prize_count'] > 0:
        reasons.append("⚠️ Phone number provided for prize claim - SCAM PATTERN")
    
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
    
    if features['has_phone'] and 'call' not in text_lower:
        reasons.append("⚠️ Contains phone number without context")
    
    # Urgency
    if features['urgency_count'] > 0:
        reasons.append(f"Creates urgency with {features['urgency_count']} urgency word(s)")
    
    # Count suspicious elements
    suspicious_count = features['high_risk_count'] + features['prize_count']
    if suspicious_count >= 2:
        reasons.append(f"⚠️ Multiple scam indicators ({suspicious_count} red flags)")
    
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
        high_risk_triggers = []
        
        # Rule 1: Asking for bank details
        if features['high_risk_count'] > 0:
            high_risk_triggers.append("bank_details")
        
        # Rule 2: Prize claims with contact info
        if features['prize_count'] > 0 and features['has_phone']:
            high_risk_triggers.append("prize_scam")
        
        # Rule 3: "Won money" requests
        if 'won' in message.lower() and ('money' in message.lower() or 'prize' in message.lower()):
            if 'bank' in message.lower() or 'share' in message.lower():
                high_risk_triggers.append("prize_scam_with_bank")
        
        # Rule 4: Direct requests for sensitive info
        if 'share your bank' in message.lower() or 'send your bank' in message.lower():
            high_risk_triggers.append("direct_bank_request")
        
        # If ANY high risk triggers, mark as phishing
        if high_risk_triggers:
            reasons = get_detailed_reasons(features, message)
            return render_template('index.html',
                                 result="⚠️ PHISHING DETECTED",
                                 result_class="phishing",
                                 confidence="99.9%",
                                 reasons=reasons,
                                 message=message)
        
        # Rule 5: Trusted Domain - Safe
        if features['trusted_domain'] == 1:
            reasons = get_detailed_reasons(features, message)
            return render_template('index.html',
                                 result="✅ SAFE MESSAGE",
                                 result_class="safe",
                                 confidence="99.9%",
                                 reasons=reasons,
                                 message=message)
        
        # Rule 6: OTP Messages - Usually safe if no other triggers
        if 'otp' in message.lower() and features['high_risk_count'] == 0:
            reasons = ["Standard OTP message", "No scam indicators detected"]
            return render_template('index.html',
                                 result="✅ SAFE MESSAGE",
                                 result_class="safe",
                                 confidence="95.0%",
                                 reasons=reasons,
                                 message=message)
        
        # ===== FALLBACK TO SAFE (if no triggers) =====
        # Since we don't have the model file here, we'll use rule-based
        # But in production with model, you'd use the model prediction
        
        # Calculate risk score
        risk_score = 0
        risk_score += features['high_risk_count'] * 50
        risk_score += features['prize_count'] * 30
        risk_score += features['has_phone'] * 20
        risk_score += features['urgency_count'] * 10
        
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

if __name__ == '__main__':
    print("\n" + "="*60)
    print("🚀 CYBERGUARD PRO - AI PHISHING DETECTOR")
    print("="*60)
    print("📡 Server running at http://127.0.0.1:5000")
    print("="*60 + "\n")
    app.run(debug=True, port=5000)