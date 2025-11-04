const express = require('express');
const path = require('path');

const app = express();
const PORT = 3002;

app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Main comparison page
app.get('/', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>MSCS535 Project 2 - Security Demo</title>
        <style>
            body { 
                font-family: Arial, sans-serif; 
                padding: 20px; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                margin: 0;
            }
            .container { max-width: 900px; margin: 0 auto; }
            .header { text-align: center; padding: 20px 0; }
            .section { 
                background: rgba(255, 255, 255, 0.1); 
                border-radius: 10px; 
                margin: 20px 0; 
                padding: 25px; 
                backdrop-filter: blur(10px);
            }
            .vulnerable { border-left: 5px solid #ff4444; }
            .secure { border-left: 5px solid #44ff44; }
            .comparison { border-left: 5px solid #4444ff; }
            .button {
                display: inline-block;
                padding: 12px 24px;
                margin: 5px;
                background: rgba(255, 255, 255, 0.2);
                color: white;
                text-decoration: none;
                border-radius: 5px;
                border: 2px solid rgba(255, 255, 255, 0.3);
                transition: all 0.3s ease;
            }
            .button:hover {
                background: rgba(255, 255, 255, 0.3);
                transform: translateY(-2px);
            }
            .vulnerable-btn { border-color: #ff4444; }
            .secure-btn { border-color: #44ff44; }
            .warning { 
                background: rgba(255, 0, 0, 0.2); 
                padding: 15px; 
                border-radius: 5px; 
                margin: 10px 0;
                border: 2px solid #ff4444;
            }
            .success { 
                background: rgba(0, 255, 0, 0.2); 
                padding: 15px; 
                border-radius: 5px; 
                margin: 10px 0;
                border: 2px solid #44ff44;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔐 MSCS535 Project 2</h1>
                <h2>JavaScript Security Vulnerabilities & Mitigations</h2>
                <p>A comprehensive demonstration of XSS attacks, code injection, and security best practices</p>
            </div>
            
            <div class="section vulnerable">
                <h2>⚠️ Part 1 & 2: VULNERABLE DEMONSTRATIONS</h2>
                <div class="warning">
                    <strong>⚠️ WARNING:</strong> These endpoints contain intentional security vulnerabilities for educational purposes!
                </div>
                
                <h3>🎯 XSS (Cross-Site Scripting) Vulnerabilities:</h3>
                <p>Demonstrates how malicious scripts can be injected into web applications.</p>
                <a href="http://localhost:3000/vulnerable/reflected" class="button vulnerable-btn" target="_blank">
                    Reflected XSS Demo
                </a>
                <a href="http://localhost:3000/vulnerable/stored" class="button vulnerable-btn" target="_blank">
                    Stored XSS Demo
                </a>
                
                <h3>💻 Dynamic Code Evaluation Vulnerabilities:</h3>
                <p>Shows how eval() and Function constructor can be exploited for arbitrary code execution.</p>
                <a href="http://localhost:3000/vulnerable/eval" class="button vulnerable-btn" target="_blank">
                    eval() Vulnerability
                </a>
                <a href="http://localhost:3000/vulnerable/function" class="button vulnerable-btn" target="_blank">
                    Function Constructor Exploit
                </a>
                
                <p><strong>🚀 Start Vulnerable Server:</strong></p>
                <code style="background: rgba(0,0,0,0.3); padding: 10px; border-radius: 5px; display: block; margin: 10px 0;">
                    npm run vulnerable
                </code>
            </div>
            
            <div class="section secure">
                <h2>✅ Part 3: SECURE IMPLEMENTATIONS</h2>
                <div class="success">
                    <strong>✅ SECURE:</strong> These endpoints demonstrate proper security mitigations and best practices.
                </div>
                
                <h3>🛡️ XSS Prevention Techniques:</h3>
                <ul>
                    <li><strong>HTML Escaping:</strong> Neutralizes dangerous HTML characters</li>
                    <li><strong>Content Security Policy:</strong> Prevents execution of injected scripts</li>
                    <li><strong>DOMPurify:</strong> Server-side HTML sanitization</li>
                </ul>
                <a href="http://localhost:3001/secure/reflected" class="button secure-btn" target="_blank">
                    Secure Input Handling
                </a>
                <a href="http://localhost:3001/secure/stored" class="button secure-btn" target="_blank">
                    Secure Comment System
                </a>
                
                <h3>🔒 Safe Code Evaluation:</h3>
                <ul>
                    <li><strong>Input Validation:</strong> Whitelist approach for allowed inputs</li>
                    <li><strong>Pattern Blocking:</strong> Dangerous keywords and functions blocked</li>
                    <li><strong>Sandboxing:</strong> Restricted execution environment</li>
                </ul>
                <a href="http://localhost:3001/secure/calculator" class="button secure-btn" target="_blank">
                    Secure Calculator
                </a>
                
                <p><strong>🚀 Start Secure Server:</strong></p>
                <code style="background: rgba(0,0,0,0.3); padding: 10px; border-radius: 5px; display: block; margin: 10px 0;">
                    npm run secure
                </code>
            </div>
            
            <div class="section comparison">
                <h2>📊 ASSIGNMENT REQUIREMENTS FULFILLED</h2>
                
                <h3>✅ Part 1: JavaScript Code Injection via Web Applications</h3>
                <ul>
                    <li>Reflected XSS vulnerability with multiple attack vectors</li>
                    <li>Stored XSS vulnerability with persistent malicious scripts</li>
                    <li>Interactive demonstrations with real attack payloads</li>
                </ul>
                
                <h3>✅ Part 2: Dynamic Evaluation of Code at Runtime</h3>
                <ul>
                    <li>eval() vulnerability allowing arbitrary code execution</li>
                    <li>Function constructor exploitation</li>
                    <li>File system access and command execution examples</li>
                </ul>
                
                <h3>✅ Part 3: Security Mitigations</h3>
                <ul>
                    <li>Content Security Policy (CSP) implementation</li>
                    <li>HTML escaping and input sanitization</li>
                    <li>DOMPurify for safe HTML rendering</li>
                    <li>Whitelist-based input validation</li>
                    <li>Safe expression evaluation without eval()</li>
                </ul>
            </div>
            
            <div class="section">
                <h2>🚀 Getting Started</h2>
                <ol>
                    <li>Install dependencies: <code>npm install</code></li>
                    <li>Run vulnerable server: <code>npm run vulnerable</code> (Port 3000)</li>
                    <li>Run secure server: <code>npm run secure</code> (Port 3001)</li>
                    <li>Compare the implementations and test various attack vectors</li>
                </ol>
                
                <p><strong>Key Learning Objectives:</strong></p>
                <ul>
                    <li>Understanding XSS attack vectors and prevention</li>
                    <li>Recognizing dangers of dynamic code evaluation</li>
                    <li>Implementing security best practices</li>
                    <li>Using Content Security Policy effectively</li>
                </ul>
            </div>
        </div>
    </body>
    </html>`);
});

app.listen(PORT, () => {
    console.log(`🎯 MAIN DEMO server running on http://localhost:${PORT}`);
    console.log('📚 Visit this URL to see the complete assignment overview.');
});
