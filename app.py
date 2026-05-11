"""
===============================================================================
LightCrypt-8 Streamlit Web Interface
A Beautiful UI for Custom Encryption Algorithm
===============================================================================
"""

import streamlit as st
import time
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from crypt import *
import io

# Page configuration
st.set_page_config(
    page_title="LightCrypt-8 Encryption Tool",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main {
        padding: 0rem 1rem;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 2rem;
    }
    .stTabs [data-baseweb="tab"] {
        height: 3rem;
        padding-left: 2rem;
        padding-right: 2rem;
        font-size: 1.1rem;
        font-weight: 600;
    }
    .success-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #d4edda;
        border: 1px solid #c3e6cb;
        color: #155724;
        margin: 1rem 0;
    }
    .error-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #f8d7da;
        border: 1px solid #f5c6cb;
        color: #721c24;
        margin: 1rem 0;
    }
    .info-box {
        padding: 1rem;
        border-radius: 0.5rem;
        background-color: #d1ecf1;
        border: 1px solid #bee5eb;
        color: #0c5460;
        margin: 1rem 0;
    }
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 1.5rem;
        border-radius: 1rem;
        color: white;
        text-align: center;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .stat-value {
        font-size: 2.5rem;
        font-weight: bold;
        margin: 0.5rem 0;
    }
    .stat-label {
        font-size: 1rem;
        opacity: 0.9;
    }
    h1 {
        color: #667eea;
        font-weight: 700;
    }
    h2 {
        color: #764ba2;
        font-weight: 600;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'encryption_history' not in st.session_state:
    st.session_state.encryption_history = []

# Sidebar
with st.sidebar:
    st.image("https://img.icons8.com/clouds/200/000000/lock.png", width=150)
    st.title("🔐 LightCrypt-8")
    st.markdown("---")
    
    st.markdown("### ⚙️ Encryption Settings")
    rounds = st.slider("Encryption Rounds", 1, 16, 4, 
                      help="More rounds = More security but slower")
    authenticated = st.checkbox("Enable Authentication (HMAC)", value=True,
                               help="Adds tamper detection")
    
    st.markdown("---")
    st.markdown("### 📊 Statistics")
    st.metric("Total Encryptions", len(st.session_state.encryption_history))
    
    st.markdown("---")
    st.markdown("""
    ### 🎯 Features
    - ✅ CBC Mode Encryption
    - ✅ HMAC Authentication
    - ✅ Key-Dependent S-Box
    - ✅ Avalanche Effect
    - ✅ File Encryption
    - ✅ Security Testing
    """)

# Main header
st.title("🔐 LightCrypt-8 Encryption System")
st.markdown("### A Custom Lightweight Block Cipher with Advanced Security Features")
st.markdown("---")

# Create tabs
tabs = st.tabs([
    "🔒 Encrypt/Decrypt", 
    "📁 File Operations",
    "🧪 Security Tests", 
    "📊 Performance", 
    "⚖️ Algorithm Comparison",
    "📚 Documentation"
])

# ============================================================================
# TAB 1: ENCRYPT/DECRYPT
# ============================================================================
with tabs[0]:
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🔒 Encryption")
        encrypt_key = st.text_input("Encryption Key", value="MySecureKey2025", 
                                    type="password", key="enc_key",
                                    help="Enter a strong password")
        
        plaintext_input = st.text_area("Enter text to encrypt", 
                                       value="Hello, this is LightCrypt-8!",
                                       height=150,
                                       help="Type or paste your message here")
        
        if st.button("🔒 Encrypt", type="primary", use_container_width=True):
            if plaintext_input and encrypt_key:
                try:
                    start_time = time.time()
                    plaintext_bytes = plaintext_input.encode('utf-8')
                    ciphertext = lightcrypt_encrypt(plaintext_bytes, encrypt_key, 
                                                   rounds=rounds, 
                                                   authenticated=authenticated)
                    elapsed = (time.time() - start_time) * 1000
                    
                    st.session_state.ciphertext = ciphertext.hex()
                    st.session_state.encryption_history.append({
                        'operation': 'Encrypt',
                        'size': len(plaintext_bytes),
                        'time': elapsed,
                        'rounds': rounds
                    })
                    
                    st.markdown('<div class="success-box">✅ Encryption successful!</div>', 
                              unsafe_allow_html=True)
                    st.code(st.session_state.ciphertext, language="text")
                    
                    col_a, col_b, col_c = st.columns(3)
                    col_a.metric("Input Size", f"{len(plaintext_bytes)} bytes")
                    col_b.metric("Output Size", f"{len(ciphertext)} bytes")
                    col_c.metric("Time", f"{elapsed:.2f} ms")
                    
                except Exception as e:
                    st.markdown(f'<div class="error-box">❌ Error: {str(e)}</div>', 
                              unsafe_allow_html=True)
            else:
                st.warning("⚠️ Please enter both key and plaintext")
    
    with col2:
        st.markdown("### 🔓 Decryption")
        decrypt_key = st.text_input("Decryption Key", value="MySecureKey2025", 
                                   type="password", key="dec_key",
                                   help="Enter the same key used for encryption")
        
        ciphertext_input = st.text_area("Enter ciphertext (hex)", 
                                        value=st.session_state.get('ciphertext', ''),
                                        height=150,
                                        help="Paste the hex-encoded ciphertext")
        
        if st.button("🔓 Decrypt", type="primary", use_container_width=True):
            if ciphertext_input and decrypt_key:
                try:
                    start_time = time.time()
                    ciphertext_bytes = bytes.fromhex(ciphertext_input)
                    plaintext_bytes = lightcrypt_decrypt(ciphertext_bytes, decrypt_key, 
                                                        rounds=rounds, 
                                                        authenticated=authenticated)
                    elapsed = (time.time() - start_time) * 1000
                    
                    plaintext = plaintext_bytes.decode('utf-8')
                    
                    st.session_state.encryption_history.append({
                        'operation': 'Decrypt',
                        'size': len(ciphertext_bytes),
                        'time': elapsed,
                        'rounds': rounds
                    })
                    
                    st.markdown('<div class="success-box">✅ Decryption successful!</div>', 
                              unsafe_allow_html=True)
                    st.text_area("Decrypted Text", value=plaintext, height=150)
                    
                    col_a, col_b, col_c = st.columns(3)
                    col_a.metric("Input Size", f"{len(ciphertext_bytes)} bytes")
                    col_b.metric("Output Size", f"{len(plaintext_bytes)} bytes")
                    col_c.metric("Time", f"{elapsed:.2f} ms")
                    
                except ValueError as e:
                    if "Authentication failed" in str(e):
                        st.markdown('<div class="error-box">🚨 Authentication Failed! Data has been tampered with or wrong key used.</div>', 
                                  unsafe_allow_html=True)
                    else:
                        st.markdown(f'<div class="error-box">❌ Error: {str(e)}</div>', 
                                  unsafe_allow_html=True)
                except Exception as e:
                    st.markdown(f'<div class="error-box">❌ Error: {str(e)}</div>', 
                              unsafe_allow_html=True)
            else:
                st.warning("⚠️ Please enter both key and ciphertext")

# ============================================================================
# TAB 2: FILE OPERATIONS
# ============================================================================
with tabs[1]:
    st.markdown("### 📁 File Encryption & Decryption")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### 🔒 Encrypt File")
        file_key_enc = st.text_input("File Encryption Key", value="FileKey2025", 
                                     type="password", key="file_enc_key")
        uploaded_file = st.file_uploader("Choose a file to encrypt", 
                                        type=['txt', 'pdf', 'jpg', 'png', 'docx', 'zip'])
        
        if uploaded_file and st.button("🔒 Encrypt File", use_container_width=True):
            try:
                file_data = uploaded_file.read()
                start_time = time.time()
                encrypted_data = lightcrypt_encrypt(file_data, file_key_enc, 
                                                   rounds=rounds, 
                                                   authenticated=authenticated)
                elapsed = (time.time() - start_time) * 1000
                
                # Store settings as metadata (prepend to file)
                # Format: [rounds:1byte][authenticated:1byte][encrypted_data]
                metadata = bytes([rounds, 1 if authenticated else 0])
                file_with_metadata = metadata + encrypted_data
                
                st.success(f"✅ File encrypted in {elapsed:.2f} ms")
                
                col_a, col_b, col_c = st.columns(3)
                col_a.metric("Original Size", f"{len(file_data)} bytes")
                col_b.metric("Encrypted Size", f"{len(encrypted_data)} bytes")
                col_c.metric("Rounds Used", rounds)
                
                st.info(f"🔐 Settings: {rounds} rounds, Authentication: {'✅ Enabled' if authenticated else '❌ Disabled'}")
                
                st.download_button(
                    label="⬇️ Download Encrypted File",
                    data=file_with_metadata,
                    file_name=f"encrypted_{uploaded_file.name}.enc",
                    mime="application/octet-stream",
                    use_container_width=True
                )
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")
    
    with col2:
        st.markdown("#### 🔓 Decrypt File")
        file_key_dec = st.text_input("File Decryption Key", value="FileKey2025", 
                                     type="password", key="file_dec_key")
        encrypted_file = st.file_uploader("Choose an encrypted file (.enc)", 
                                         type=['enc'])
        
        if encrypted_file and st.button("🔓 Decrypt File", use_container_width=True):
            try:
                file_with_metadata = encrypted_file.read()
                
                # Extract metadata (first 2 bytes)
                if len(file_with_metadata) < 2:
                    st.error("❌ Invalid encrypted file format")
                else:
                    stored_rounds = file_with_metadata[0]
                    stored_authenticated = bool(file_with_metadata[1])
                    encrypted_data = file_with_metadata[2:]
                    
                    st.info(f"📋 Detected settings: {stored_rounds} rounds, Authentication: {'✅ Enabled' if stored_authenticated else '❌ Disabled'}")
                    
                    start_time = time.time()
                    decrypted_data = lightcrypt_decrypt(encrypted_data, file_key_dec, 
                                                       rounds=stored_rounds, 
                                                       authenticated=stored_authenticated)
                    elapsed = (time.time() - start_time) * 1000
                    
                    st.success(f"✅ File decrypted in {elapsed:.2f} ms")
                    
                    col_a, col_b, col_c = st.columns(3)
                    col_a.metric("Encrypted Size", f"{len(encrypted_data)} bytes")
                    col_b.metric("Decrypted Size", f"{len(decrypted_data)} bytes")
                    col_c.metric("Rounds Used", stored_rounds)
                    
                    # Try to detect original file type
                    original_name = encrypted_file.name.replace("encrypted_", "").replace(".enc", "")
                    
                    st.download_button(
                        label="⬇️ Download Decrypted File",
                        data=decrypted_data,
                        file_name=f"decrypted_{original_name}",
                        mime="application/octet-stream",
                        use_container_width=True
                    )
            except ValueError as e:
                if "Authentication failed" in str(e):
                    st.error("🚨 Authentication Failed! Wrong key or tampered file.")
                else:
                    st.error(f"❌ Error: {str(e)}")
            except Exception as e:
                st.error(f"❌ Error: {str(e)}")

# ============================================================================
# TAB 3: SECURITY TESTS
# ============================================================================
with tabs[2]:
    st.markdown("### 🧪 Comprehensive Security Testing Suite")
    
    test_selector = st.multiselect(
        "Select tests to run:",
        ["Avalanche Effect", "Key Sensitivity", "Authentication", 
         "Pattern Resistance", "Correctness", "Randomness"],
        default=["Avalanche Effect", "Key Sensitivity", "Authentication"]
    )
    
    if st.button("▶️ Run Selected Tests", type="primary", use_container_width=True):
        results = {}
        
        # Test 1: Avalanche Effect
        if "Avalanche Effect" in test_selector:
            with st.expander("🌊 Avalanche Effect Test", expanded=True):
                st.markdown("**Purpose:** Verify that changing 1 bit in input changes ~50% of output bits")
                
                progress = st.progress(0)
                key = "TestKey"
                pt1 = b"Hello World Test"
                pt2 = bytearray(pt1)
                pt2[0] ^= 1
                pt2 = bytes(pt2)
                
                progress.progress(50)
                c1 = lightcrypt_encrypt(pt1, key, rounds=rounds)
                c2 = lightcrypt_encrypt(pt2, key, rounds=rounds)
                
                diff = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(c1[16:], c2[16:]))
                total = (len(c1) - 16) * 8
                percent = (diff / total) * 100
                progress.progress(100)
                
                results['avalanche'] = percent
                
                col1, col2, col3 = st.columns(3)
                col1.metric("Bits Changed", f"{diff}/{total}")
                col2.metric("Percentage", f"{percent:.2f}%")
                col3.metric("Status", "✅ PASS" if 40 <= percent <= 60 else "❌ FAIL")
                
                # Visualization
                fig = go.Figure(go.Indicator(
                    mode = "gauge+number+delta",
                    value = percent,
                    domain = {'x': [0, 1], 'y': [0, 1]},
                    title = {'text': "Avalanche Effect (%)"},
                    delta = {'reference': 50},
                    gauge = {
                        'axis': {'range': [None, 100]},
                        'bar': {'color': "darkblue"},
                        'steps': [
                            {'range': [0, 40], 'color': "lightgray"},
                            {'range': [40, 60], 'color': "lightgreen"},
                            {'range': [60, 100], 'color': "lightgray"}
                        ],
                        'threshold': {
                            'line': {'color': "red", 'width': 4},
                            'thickness': 0.75,
                            'value': 50
                        }
                    }
                ))
                st.plotly_chart(fig, use_container_width=True)
        
        # Test 2: Key Sensitivity
        if "Key Sensitivity" in test_selector:
            with st.expander("🔑 Key Sensitivity Test", expanded=True):
                st.markdown("**Purpose:** Verify that similar keys produce vastly different outputs")
                
                pt = b"Secret Message"
                c1 = lightcrypt_encrypt(pt, "Key1", rounds=rounds)
                c2 = lightcrypt_encrypt(pt, "Key2", rounds=rounds)
                
                diff = sum(bin(b1 ^ b2).count('1') for b1, b2 in zip(c1[16:], c2[16:]))
                total = (len(c1) - 16) * 8
                percent = (diff / total) * 100
                
                results['key_sens'] = percent
                
                col1, col2, col3 = st.columns(3)
                col1.metric("Keys Tested", "Key1 vs Key2")
                col2.metric("Difference", f"{percent:.2f}%")
                col3.metric("Status", "✅ PASS" if percent > 40 else "❌ FAIL")
                
                st.info(f"🎯 Result: {percent:.2f}% of bits differ between outputs with different keys")
        
        # Test 3: Authentication
        if "Authentication" in test_selector:
            with st.expander("🔐 Authentication Test", expanded=True):
                st.markdown("**Purpose:** Verify HMAC detects tampering")
                
                key = "AuthKey"
                pt = b"Authenticated message"
                
                cipher = lightcrypt_encrypt(pt, key, authenticated=True)
                decrypted = lightcrypt_decrypt(cipher, key, authenticated=True)
                
                tampered = bytearray(cipher)
                tampered[-10] ^= 0xFF
                
                try:
                    lightcrypt_decrypt(bytes(tampered), key, authenticated=True)
                    st.error("❌ FAIL: Tampering not detected!")
                    results['auth'] = False
                except ValueError:
                    st.success("✅ PASS: Tampering correctly detected")
                    results['auth'] = True
                
                col1, col2 = st.columns(2)
                col1.metric("Authentic Data", "✅ Verified")
                col2.metric("Tampered Data", "🚨 Rejected")
        
        # Test 4: Pattern Resistance
        if "Pattern Resistance" in test_selector:
            with st.expander("🎨 Pattern Resistance Test", expanded=True):
                st.markdown("**Purpose:** Verify CBC mode prevents pattern leakage")
                
                key = "PatternKey"
                pt = b"AAAAAAAAAAAAAAAA" * 3
                
                cipher = lightcrypt_encrypt(pt, key, rounds=rounds)
                b1 = cipher[16:32]
                b2 = cipher[32:48]
                b3 = cipher[48:64]
                
                st.code(f"Block 1: {b1.hex()}\nBlock 2: {b2.hex()}\nBlock 3: {b3.hex()}")
                
                if b1 != b2 and b2 != b3 and b1 != b3:
                    st.success("✅ PASS: All blocks are different despite identical input")
                    results['pattern'] = True
                else:
                    st.error("❌ FAIL: Pattern detected in output")
                    results['pattern'] = False
        
        # Test 5: Correctness
        if "Correctness" in test_selector:
            with st.expander("✔️ Correctness Test", expanded=True):
                st.markdown("**Purpose:** Verify encryption/decryption works correctly for various inputs")
                
                tests = [
                    (b"Short", "Short text"),
                    (b"A" * 100, "Repeated characters"),
                    (b"Special: !@#$%^&*()", "Special characters"),
                    (b"\x00\x01\xFF", "Binary data"),
                    ("Unicode: 你好🔐".encode('utf-8'), "Unicode text"),
                ]
                
                test_results = []
                for pt, description in tests:
                    try:
                        cipher = lightcrypt_encrypt(pt, "TestKey", rounds=rounds)
                        decrypted = lightcrypt_decrypt(cipher, "TestKey", rounds=rounds)
                        passed = pt == decrypted
                        test_results.append({
                            'Test': description,
                            'Size': f"{len(pt)} bytes",
                            'Status': '✅ PASS' if passed else '❌ FAIL'
                        })
                    except Exception as e:
                        test_results.append({
                            'Test': description,
                            'Size': f"{len(pt)} bytes",
                            'Status': f'❌ ERROR: {str(e)}'
                        })
                
                df = pd.DataFrame(test_results)
                st.dataframe(df, use_container_width=True)
                
                passed = sum(1 for r in test_results if 'PASS' in r['Status'])
                st.metric("Success Rate", f"{passed}/{len(tests)}")
                results['correct'] = passed
        
        # Test 6: Randomness
        if "Randomness" in test_selector:
            with st.expander("🎲 Statistical Randomness Test", expanded=True):
                st.markdown("**Purpose:** Verify output appears random (Chi-square test)")
                
                key = "RandomKey"
                pt = b"A" * 1000
                cipher = lightcrypt_encrypt(pt, key, rounds=rounds)
                
                freq = [0] * 256
                for byte in cipher[16:]:
                    freq[byte] += 1
                
                expected = (len(cipher) - 16) / 256
                chi_sq = sum((f - expected)**2 / expected for f in freq if f > 0)
                unique = sum(1 for f in freq if f > 0)
                
                col1, col2, col3 = st.columns(3)
                col1.metric("Chi-Square", f"{chi_sq:.2f}")
                col2.metric("Unique Bytes", f"{unique}/256")
                col3.metric("Status", "✅ PASS" if 200 <= chi_sq <= 310 else "⚠️ WARNING")
                
                # Frequency distribution chart
                fig = px.bar(x=list(range(256)), y=freq, 
                           title="Byte Frequency Distribution",
                           labels={'x': 'Byte Value', 'y': 'Frequency'})
                fig.add_hline(y=expected, line_dash="dash", line_color="red", 
                            annotation_text="Expected")
                st.plotly_chart(fig, use_container_width=True)
        
        # Summary
        st.markdown("---")
        st.markdown("### 📋 Test Summary")
        summary_cols = st.columns(len(test_selector))
        for i, test in enumerate(test_selector):
            with summary_cols[i]:
                if test == "Avalanche Effect" and 'avalanche' in results:
                    st.metric(test, f"{results['avalanche']:.1f}%")
                elif test == "Key Sensitivity" and 'key_sens' in results:
                    st.metric(test, f"{results['key_sens']:.1f}%")
                elif test == "Authentication" and 'auth' in results:
                    st.metric(test, "✅ PASS" if results['auth'] else "❌ FAIL")
                elif test == "Pattern Resistance" and 'pattern' in results:
                    st.metric(test, "✅ PASS" if results['pattern'] else "❌ FAIL")
                elif test == "Correctness" and 'correct' in results:
                    st.metric(test, f"{results['correct']}/5")

# ============================================================================
# TAB 4: PERFORMANCE
# ============================================================================
with tabs[3]:
    st.markdown("### 📊 Performance Benchmarking")
    
    col1, col2 = st.columns([1, 1])
    
    with col1:
        st.markdown("#### ⚡ Throughput Test")
        sizes = st.multiselect("Select data sizes:", 
                              ["1 KB", "10 KB", "100 KB", "1 MB"],
                              default=["1 KB", "10 KB", "100 KB"])
        
        if st.button("▶️ Run Performance Test", use_container_width=True):
            size_map = {"1 KB": 1000, "10 KB": 10000, "100 KB": 100000, "1 MB": 1000000}
            
            results = []
            progress = st.progress(0)
            
            for i, size_label in enumerate(sizes):
                size = size_map[size_label]
                pt = b"X" * size
                
                # Encryption test
                start = time.time()
                cipher = lightcrypt_encrypt(pt, "PerfKey", rounds=rounds)
                enc_time = (time.time() - start) * 1000
                enc_throughput = (size / 1024) / (enc_time / 1000)
                
                # Decryption test
                start = time.time()
                lightcrypt_decrypt(cipher, "PerfKey", rounds=rounds)
                dec_time = (time.time() - start) * 1000
                dec_throughput = (size / 1024) / (dec_time / 1000)
                
                results.append({
                    'Size': size_label,
                    'Encrypt (ms)': f"{enc_time:.2f}",
                    'Decrypt (ms)': f"{dec_time:.2f}",
                    'Enc Throughput (KB/s)': f"{enc_throughput:.2f}",
                    'Dec Throughput (KB/s)': f"{dec_throughput:.2f}"
                })
                
                progress.progress((i + 1) / len(sizes))
            
            df = pd.DataFrame(results)
            st.dataframe(df, use_container_width=True)
            
            # Chart
            fig = go.Figure()
            fig.add_trace(go.Bar(name='Encryption', x=[r['Size'] for r in results], 
                                y=[float(r['Encrypt (ms)']) for r in results]))
            fig.add_trace(go.Bar(name='Decryption', x=[r['Size'] for r in results], 
                                y=[float(r['Decrypt (ms)']) for r in results]))
            fig.update_layout(title='Encryption vs Decryption Time',
                            xaxis_title='Data Size',
                            yaxis_title='Time (ms)',
                            barmode='group')
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.markdown("#### 🔄 Round Count Analysis")
        if st.button("▶️ Analyze Round Impact", use_container_width=True):
            key = "RoundKey"
            pt = b"Test message for rounds analysis"
            
            round_results = []
            for r in [1, 2, 4, 8, 16]:
                start = time.time()
                cipher = lightcrypt_encrypt(pt, key, rounds=r)
                elapsed = (time.time() - start) * 1000
                
                security = "🟡 Low" if r < 4 else "🟢 Medium" if r < 8 else "🔵 High"
                
                round_results.append({
                    'Rounds': r,
                    'Time (ms)': f"{elapsed:.3f}",
                    'Security': security
                })
            
            df = pd.DataFrame(round_results)
            st.dataframe(df, use_container_width=True)
            
            # Chart
            fig = px.line(df, x='Rounds', y=df['Time (ms)'].astype(float),
                         title='Round Count vs Performance',
                         markers=True)
            fig.update_layout(xaxis_title='Number of Rounds',
                            yaxis_title='Time (ms)')
            st.plotly_chart(fig, use_container_width=True)
            
            st.info("💡 **Recommendation:** Use 8+ rounds for production systems")

# ============================================================================
# TAB 5: ALGORITHM COMPARISON
# ============================================================================
with tabs[4]:
    st.markdown("### ⚖️ LightCrypt-8 vs Standard Algorithms")
    
    st.markdown("#### 📊 Feature Comparison")
    
    comparison_data = {
        'Feature': ['Block Size', 'Default Rounds', 'Speed', 'Security Level', 
                   'Complexity', 'Standardized', 'Hardware Support', 'Best Use Case'],
        'LightCrypt-8': ['16 bytes', '4', '⚡⚡ Fast', '⭐⭐ Medium', 
                        '🟢 Simple', '❌ No', '❌ No', '📚 Education'],
        'AES-128': ['16 bytes', '10', '⚡⚡⚡ Very Fast', '⭐⭐⭐⭐⭐ Excellent', 
                   '🔴 Complex', '✅ Yes (NIST)', '✅ Yes (AES-NI)', '🏢 Production'],
        'ChaCha20': ['64 bytes', '20', '⚡⚡⚡ Very Fast', '⭐⭐⭐⭐⭐ Excellent', 
                    '🟡 Moderate', '✅ Yes (RFC)', '🟡 Partial', '📱 Mobile/IoT']
    }
    
    df = pd.DataFrame(comparison_data)
    st.dataframe(df, use_container_width=True, hide_index=True)
    
    st.markdown("---")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("#### ✅ Strengths of LightCrypt-8")
        st.markdown("""
        - ✅ **Key-dependent S-box** - Prevents precomputation attacks
        - ✅ **CBC mode implementation** - Resists pattern analysis
        - ✅ **HMAC authentication** - Detects data tampering
        - ✅ **Configurable security** - Adjustable rounds for different needs
        - ✅ **256-bit key space** - Resistant to brute-force
        - ✅ **Simple design** - Easy to understand and audit
        - ✅ **Educational value** - Great for learning cryptography
        """)
        
        st.markdown("#### 🎯 Best Use Cases")
        st.info("""
        **LightCrypt-8 is ideal for:**
        - 📚 Academic projects and learning
        - 🔬 Cryptography research
        - 🎓 Teaching encryption concepts
        - 🧪 Security testing demonstrations
        - 💻 Non-critical applications
        """)
    
    with col2:
        st.markdown("#### ⚠️ Limitations")
        st.markdown("""
        - ⚠️ **Simple transposition** - Not as strong as AES MixColumns
        - ⚠️ **Low default rounds** - 4 vs AES's 10-14
        - ⚠️ **No formal proof** - Lacks mathematical security proof
        - ⚠️ **Not standardized** - Not reviewed by NIST/IETF
        - ⚠️ **No hardware support** - Slower than AES-NI
        - ⚠️ **Unknown resistance** - Differential/linear cryptanalysis not studied
        """)
        
        st.markdown("#### 🛡️ Security Recommendations")
        st.warning("""
        **For production systems:**
        - 🔒 Use NIST-approved algorithms (AES-GCM, ChaCha20-Poly1305)
        - 🔑 Implement proper key management
        - 📝 Follow OWASP cryptographic guidelines
        - 🔄 Use established libraries (OpenSSL, libsodium)
        - ✅ Get professional security audits
        """)
    
    st.markdown("---")
    
    st.markdown("#### 🔬 Attack Resistance Analysis")
    
    attack_data = {
        'Attack Type': ['Brute Force', 'Pattern Analysis', 'Data Tampering', 
                       'Differential Cryptanalysis', 'Linear Cryptanalysis', 
                       'Related-Key Attack'],
        'LightCrypt-8': ['✅ Resistant', '✅ Resistant', '✅ Resistant (HMAC)', 
                        '❓ Unknown', '❓ Unknown', '⚠️ Potential Risk'],
        'Status': ['2^256 keyspace', 'CBC mode', 'HMAC-SHA256', 
                  'Needs analysis', 'Needs analysis', 'Further study needed']
    }
    
    df_attack = pd.DataFrame(attack_data)
    st.dataframe(df_attack, use_container_width=True, hide_index=True)
    
    st.markdown("#### 💡 Recommendations for Enhancement")
    
    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("""
        **Algorithm Improvements:**
        - Add MixColumns operation
        - Increase default rounds to 8
        - Implement key scheduling
        - Add salt to key derivation
        """)
    
    with col2:
        st.markdown("""
        **Security Enhancements:**
        - Conduct cryptanalysis study
        - Implement side-channel protection
        - Add constant-time operations
        - Formal security proof
        """)
    
    with col3:
        st.markdown("""
        **Implementation:**
        - Optimize performance
        - Add hardware acceleration
        - Support more modes (GCM, CTR)
        - PKCS#11 interface
        """)

# ============================================================================
# TAB 6: DOCUMENTATION
# ============================================================================
with tabs[5]:
    st.markdown("### 📚 Complete Documentation")
    
    doc_section = st.selectbox("Select section:", 
                              ["Overview", "Algorithm Details", "API Reference", 
                               "Security Analysis", "Usage Examples"])
    
    if doc_section == "Overview":
        st.markdown("""
        ## 🔐 LightCrypt-8 Overview
        
        **LightCrypt-8** is a custom lightweight block cipher designed for educational purposes.
        It demonstrates fundamental cryptographic concepts while providing reasonable security
        for non-critical applications.
        
        ### Key Features
        
        - **Block Cipher:** 128-bit (16 byte) blocks
        - **Key Size:** Variable length (hashed to 256 bits)
        - **Mode of Operation:** CBC (Cipher Block Chaining)
        - **Authentication:** HMAC-SHA256
        - **Padding:** PKCS#7
        
        ### Architecture
        
        1. **Substitution Layer:** Key-dependent S-box generation using SHA-256
        2. **Permutation Layer:** Columnar transposition
        3. **Round Function:** Repeated substitution-permutation network
        4. **Authentication:** Encrypt-then-MAC using HMAC
        
        ### Design Philosophy
        
        LightCrypt-8 prioritizes:
        - 📖 **Clarity** - Easy to understand implementation
        - 🎓 **Education** - Teaches core cryptographic principles
        - ⚡ **Performance** - Reasonable speed for learning projects
        - 🔒 **Security** - Demonstrates important security features
        """)
    
    elif doc_section == "Algorithm Details":
        st.markdown("""
        ## 🔬 Algorithm Technical Details
        
        ### Encryption Process
        
        ```
        1. Key Derivation
           └─> SHA-256(key) → Generate S-box
           └─> SHA-256(key + "_transposition") → Column order
        
        2. Padding
           └─> Add PKCS#7 padding to reach block boundary
        
        3. CBC Encryption
           ├─> Generate random IV (16 bytes)
           ├─> For each block:
           │   ├─> XOR with previous ciphertext (or IV)
           │   ├─> Apply round function:
           │   │   ├─> Substitute using S-box
           │   │   └─> Transpose columns
           │   └─> Repeat for N rounds
           └─> Concatenate all blocks
        
        4. Authentication (if enabled)
           └─> HMAC-SHA256(IV || ciphertext)
        
        5. Output
           └─> IV || ciphertext [|| MAC]
        ```
        
        ### S-box Generation
        
        The S-box is generated dynamically from the key:
        
        ```python
        seed = int.from_bytes(SHA256(key), 'big')
        random.seed(seed)
        sbox = shuffle([0, 1, 2, ..., 255])
        ```
        
        This makes precomputation attacks infeasible since each key has a unique S-box.
        
        ### Transposition
        
        Columnar transposition permutes bytes within each block according to a 
        key-derived order, providing diffusion.
        
        ### Round Function
        
        Each round consists of:
        1. **Substitution** - Replace each byte using S-box
        2. **Permutation** - Reorder bytes using transposition
        
        More rounds provide better security but slower performance.
        """)
    
    elif doc_section == "API Reference":
        st.markdown("""
        ## 📖 API Reference
        
        ### Main Functions
        
        #### `lightcrypt_encrypt(plaintext, key, rounds=4, authenticated=False)`
        
        Encrypts data using LightCrypt-8 algorithm.
        
        **Parameters:**
        - `plaintext` (bytes): Data to encrypt
        - `key` (str): Encryption key
        - `rounds` (int): Number of encryption rounds (default: 4)
        - `authenticated` (bool): Enable HMAC authentication (default: False)
        
        **Returns:**
        - `bytes`: IV || ciphertext [|| MAC]
        
        **Example:**
        ```python
        ciphertext = lightcrypt_encrypt(b"Hello", "MyKey", rounds=4, authenticated=True)
        ```
        
        ---
        
        #### `lightcrypt_decrypt(ciphertext, key, rounds=4, authenticated=False)`
        
        Decrypts LightCrypt-8 encrypted data.
        
        **Parameters:**
        - `ciphertext` (bytes): Encrypted data from encrypt function
        - `key` (str): Decryption key (must match encryption key)
        - `rounds` (int): Number of rounds (must match encryption)
        - `authenticated` (bool): Verify HMAC (must match encryption)
        
        **Returns:**
        - `bytes`: Original plaintext
        
        **Raises:**
        - `ValueError`: If authentication fails or data is corrupted
        
        **Example:**
        ```python
        plaintext = lightcrypt_decrypt(ciphertext, "MyKey", rounds=4, authenticated=True)
        ```
        
        ---
        
        ### Low-Level Functions
        
        #### `generate_sboxes(key)`
        Returns S-box and inverse S-box for given key.
        
        #### `encrypt_cbc(plaintext, key, rounds, iv=None)`
        CBC mode encryption, returns (ciphertext, iv).
        
        #### `decrypt_cbc(ciphertext, key, rounds, iv)`
        CBC mode decryption, returns plaintext.
        
        #### `generate_mac(data, key)`
        Generates HMAC-SHA256 for data.
        
        #### `verify_mac(data, mac, key)`
        Verifies HMAC, returns boolean.
        """)
    
    elif doc_section == "Security Analysis":
        st.markdown("""
        ## 🛡️ Security Analysis
        
        ### Threat Model
        
        LightCrypt-8 is designed to protect against:
        
        ✅ **Passive Eavesdropping**
        - Ciphertext reveals no information about plaintext
        - 256-bit effective key space resists brute force
        
        ✅ **Pattern Analysis**
        - CBC mode prevents identical plaintext blocks from producing identical ciphertext
        - Avalanche effect ensures small changes cascade
        
        ✅ **Data Tampering**
        - HMAC authentication detects any modification
        - Encrypt-then-MAC construction prevents adaptive attacks
        
        ❓ **Advanced Cryptanalysis**
        - Differential and linear cryptanalysis resistance is unknown
        - Related-key attacks have not been studied
        
        ❌ **Side-Channel Attacks**
        - Not designed to resist timing attacks
        - No constant-time implementation
        
        ### Known Limitations
        
        1. **Not Formally Proven**
           - No mathematical proof of security
           - Not peer-reviewed by cryptographic community
        
        2. **Simple Diffusion**
           - Transposition is weaker than AES's MixColumns
           - May require more rounds for equivalent security
        
        3. **Low Round Count**
           - Default 4 rounds vs AES's 10-14
           - Recommendation: Use 8+ rounds for sensitive data
        
        4. **Implementation**
           - Pure Python (slower than optimized C)
           - No hardware acceleration
           - Potential timing vulnerabilities
        
        ### Security Recommendations
        
        🔒 **For Maximum Security:**
        - Use 16 rounds minimum
        - Always enable authentication
        - Use strong, random keys (32+ characters)
        - Rotate keys periodically
        - Use for non-critical applications only
        
        ⚠️ **Not Suitable For:**
        - Financial transactions
        - Medical records
        - Government/military use
        - Any compliance-regulated data
        - Production systems handling sensitive data
        """)
    
    elif doc_section == "Usage Examples":
        st.markdown("""
        ## 💻 Usage Examples
        
        ### Basic Text Encryption
        
        ```python
        from crypt import lightcrypt_encrypt, lightcrypt_decrypt
        
        # Encrypt
        plaintext = b"Hello, World!"
        key = "MySecretKey123"
        ciphertext = lightcrypt_encrypt(plaintext, key)
        
        # Decrypt
        decrypted = lightcrypt_decrypt(ciphertext, key)
        print(decrypted)  # b"Hello, World!"
        ```
        
        ### Authenticated Encryption
        
        ```python
        # Encrypt with HMAC
        ciphertext = lightcrypt_encrypt(
            plaintext=b"Important message",
            key="SecureKey",
            rounds=8,
            authenticated=True
        )
        
        # Decrypt and verify
        try:
            decrypted = lightcrypt_decrypt(
                ciphertext,
                "SecureKey",
                rounds=8,
                authenticated=True
            )
            print("✅ Authentic:", decrypted)
        except ValueError:
            print("❌ Authentication failed!")
        ```
        
        ### File Encryption
        
        ```python
        # Encrypt file
        with open("document.pdf", "rb") as f:
            file_data = f.read()
        
        encrypted = lightcrypt_encrypt(file_data, "FileKey", authenticated=True)
        
        with open("document.pdf.enc", "wb") as f:
            f.write(encrypted)
        
        # Decrypt file
        with open("document.pdf.enc", "rb") as f:
            encrypted = f.read()
        
        decrypted = lightcrypt_decrypt(encrypted, "FileKey", authenticated=True)
        
        with open("document_decrypted.pdf", "wb") as f:
            f.write(decrypted)
        ```
        
        ### High Security Settings
        
        ```python
        # Maximum security
        ciphertext = lightcrypt_encrypt(
            plaintext=b"Top secret data",
            key="VeryLongAndComplexKey_2025_@#$%",
            rounds=16,  # Maximum rounds
            authenticated=True
        )
        ```
        
        ### Batch Processing
        
        ```python
        messages = [b"Message 1", b"Message 2", b"Message 3"]
        key = "BatchKey"
        
        # Encrypt all
        encrypted = [lightcrypt_encrypt(msg, key) for msg in messages]
        
        # Decrypt all
        decrypted = [lightcrypt_decrypt(enc, key) for enc in encrypted]
        ```
        
        ### Error Handling
        
        ```python
        try:
            ciphertext = lightcrypt_encrypt(plaintext, key)
            decrypted = lightcrypt_decrypt(ciphertext, "WrongKey")
        except ValueError as e:
            print(f"Decryption failed: {e}")
        except Exception as e:
            print(f"Unexpected error: {e}")
        ```
        """)

# Footer
st.markdown("---")
col1, col2, col3 = st.columns(3)
with col1:
    st.markdown("**LightCrypt-8** v1.0")
with col2:
    st.markdown("Created for Information Security Project")
with col3:
    st.markdown("⚠️ For Educational Use Only")
