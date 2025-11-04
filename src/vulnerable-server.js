const express = require('express');
const path = require('path');

const app = express();
const PORT = 3000;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static('public'));

// PART 1: VULNERABLE XSS ENDPOINTS
// Reflected XSS - directly outputs user input without sanitization
app.get('/vulnerable/reflected', (req, res) => {
    const userInput = req.query.input || '';
    
    // VULNERABILITY: Direct insertion of user input into HTML
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerable Reflected XSS</title>
        <style>
            body { font-family: Arial, sans-serif; padding: 20px; }
            .container { max-width: 600px; margin: 0 auto; }
            .vulnerable { color: red; font-weight: bold; }
            .demo-box { border: 2px solid red; padding: 15px; margin: 10px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Part 1: Reflected XSS Vulnerability</h1>
            <p class="vulnerable">⚠️ This page is intentionally vulnerable!</p>
            
            <form method="GET">
                <label for="input">Enter some text:</label><br>
                <input type="text" name="input" value="${userInput}" style="width: 300px; padding: 5px;">
                <button type="submit">Submit</button>
            </form>
            
            <div class="demo-box">
                <h3>Your input was:</h3>
                <div>${userInput}</div>
            </div>
            
            <h3>Try these XSS payloads:</h3>
            <ul>
                <li><code>&lt;script&gt;alert('XSS!')&lt;/script&gt;</code></li>
                <li><code>&lt;img src=x onerror="alert('Image XSS')"&gt;</code></li>
                <li><code>&lt;svg onload="alert('SVG XSS')"&gt;&lt;/svg&gt;</code></li>
            </ul>
        </div>
    </body>
    </html>`;
    
    res.send(html);
});

// Stored XSS simulation with in-memory storage
let comments = [];

app.get('/vulnerable/stored', (req, res) => {
    // VULNERABILITY: Stored XSS - comments are rendered without sanitization
    const commentsHtml = comments.map(comment => 
        `<div class="comment">
            <strong>${comment.name}:</strong> ${comment.message}
            <small>(${comment.timestamp})</small>
        </div>`
    ).join('');
    
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerable Stored XSS</title>
        <style>
            body { font-family: Arial, sans-serif; padding: 20px; }
            .container { max-width: 600px; margin: 0 auto; }
            .vulnerable { color: red; font-weight: bold; }
            .comment { border-bottom: 1px solid #ccc; padding: 10px 0; }
            .demo-box { border: 2px solid red; padding: 15px; margin: 10px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Part 1: Stored XSS Vulnerability</h1>
            <p class="vulnerable">⚠️ This page is intentionally vulnerable!</p>
            
            <form method="POST" action="/vulnerable/stored">
                <div>
                    <label for="name">Name:</label><br>
                    <input type="text" name="name" required style="width: 200px; padding: 5px;">
                </div><br>
                <div>
                    <label for="message">Comment:</label><br>
                    <textarea name="message" required style="width: 400px; height: 80px; padding: 5px;"></textarea>
                </div><br>
                <button type="submit">Post Comment</button>
            </form>
            
            <div class="demo-box">
                <h3>Comments:</h3>
                ${commentsHtml}
            </div>
            
            <h3>Try posting these XSS payloads:</h3>
            <ul>
                <li><code>&lt;script&gt;alert('Stored XSS!')&lt;/script&gt;</code></li>
                <li><code>&lt;img src=x onerror="document.body.style.backgroundColor='red'"&gt;</code></li>
            </ul>
            
            <p><a href="/vulnerable/stored/clear">Clear Comments</a></p>
        </div>
    </body>
    </html>`;
    
    res.send(html);
});

app.post('/vulnerable/stored', (req, res) => {
    const { name, message } = req.body;
    
    // VULNERABILITY: No sanitization before storing
    comments.push({
        name: name,
        message: message,
        timestamp: new Date().toLocaleString()
    });
    
    res.redirect('/vulnerable/stored');
});

app.get('/vulnerable/stored/clear', (req, res) => {
    comments = [];
    res.redirect('/vulnerable/stored');
});

// PART 2: DYNAMIC CODE EVALUATION VULNERABILITIES
app.get('/vulnerable/eval', (req, res) => {
    const expression = req.query.expr || '';
    let result = '';
    let error = '';
    
    if (expression) {
        try {
            // VULNERABILITY: Using eval() with user input
            result = eval(expression);
        } catch (e) {
            error = e.message;
        }
    }
    
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerable Dynamic Code Evaluation</title>
        <style>
            body { font-family: Arial, sans-serif; padding: 20px; }
            .container { max-width: 600px; margin: 0 auto; }
            .vulnerable { color: red; font-weight: bold; }
            .result { background: #f0f0f0; padding: 10px; margin: 10px 0; }
            .error { background: #ffebee; color: red; padding: 10px; margin: 10px 0; }
            .demo-box { border: 2px solid red; padding: 15px; margin: 10px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Part 2: Dynamic Code Evaluation Vulnerability</h1>
            <p class="vulnerable">⚠️ This calculator uses eval() - extremely dangerous!</p>
            
            <form method="GET">
                <label for="expr">Enter JavaScript expression:</label><br>
                <input type="text" name="expr" value="${expression}" 
                       style="width: 400px; padding: 5px;" placeholder="2 + 2">
                <button type="submit">Evaluate</button>
            </form>
            
            ${result ? `<div class="result"><strong>Result:</strong> ${result}</div>` : ''}
            ${error ? `<div class="error"><strong>Error:</strong> ${error}</div>` : ''}
            
            <div class="demo-box">
                <h3>Dangerous payloads to try:</h3>
                <ul>
                    <li><code>require('fs').readdirSync('.')</code> - File system access</li>
                    <li><code>process.env</code> - Environment variables</li>
                    <li><code>require('child_process').execSync('whoami')</code> - Command execution</li>
                    <li><code>global.process.exit()</code> - Crash the server</li>
                </ul>
            </div>
        </div>
    </body>
    </html>`;
    
    res.send(html);
});

// Function constructor vulnerability
app.get('/vulnerable/function', (req, res) => {
    const code = req.query.code || '';
    let result = '';
    let error = '';
    
    if (code) {
        try {
            // VULNERABILITY: Using Function constructor with user input
            const dynamicFunction = new Function('return ' + code);
            result = dynamicFunction();
        } catch (e) {
            error = e.message;
        }
    }
    
    const html = `
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerable Function Constructor</title>
        <style>
            body { font-family: Arial, sans-serif; padding: 20px; }
            .container { max-width: 600px; margin: 0 auto; }
            .vulnerable { color: red; font-weight: bold; }
            .result { background: #f0f0f0; padding: 10px; margin: 10px 0; }
            .error { background: #ffebee; color: red; padding: 10px; margin: 10px 0; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Part 2: Function Constructor Vulnerability</h1>
            <p class="vulnerable">⚠️ This uses Function constructor - also dangerous!</p>
            
            <form method="GET">
                <label for="code">Enter code to execute:</label><br>
                <textarea name="code" style="width: 400px; height: 80px; padding: 5px;">${code}</textarea><br><br>
                <button type="submit">Execute</button>
            </form>
            
            ${result ? `<div class="result"><strong>Result:</strong> ${result}</div>` : ''}
            ${error ? `<div class="error"><strong>Error:</strong> ${error}</div>` : ''}
        </div>
    </body>
    </html>`;
    
    res.send(html);
});

// Main vulnerable demo page
app.get('/', (req, res) => {
    res.send(`
    <!DOCTYPE html>
    <html>
    <head>
        <title>MSCS535 Security Vulnerabilities Demo</title>
        <style>
            body { font-family: Arial, sans-serif; padding: 20px; }
            .container { max-width: 800px; margin: 0 auto; }
            .section { border: 2px solid #ddd; margin: 20px 0; padding: 20px; }
            .vulnerable { background: #ffebee; border-color: red; }
            .secure { background: #e8f5e8; border-color: green; }
            .warning { color: red; font-weight: bold; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>MSCS535 Project 2: JavaScript Security Vulnerabilities</h1>
            
            <div class="section vulnerable">
                <h2>⚠️ VULNERABLE DEMONSTRATIONS</h2>
                <p class="warning">These endpoints are intentionally insecure!</p>
                
                <h3>Part 1: XSS Vulnerabilities</h3>
                <ul>
                    <li><a href="/vulnerable/reflected">Reflected XSS</a> - User input directly inserted into HTML</li>
                    <li><a href="/vulnerable/stored">Stored XSS</a> - Malicious scripts stored and executed</li>
                </ul>
                
                <h3>Part 2: Dynamic Code Evaluation</h3>
                <ul>
                    <li><a href="/vulnerable/eval">eval() Vulnerability</a> - Arbitrary code execution</li>
                    <li><a href="/vulnerable/function">Function Constructor</a> - Dynamic function creation</li>
                </ul>
            </div>
            
            <div class="section secure">
                <h2>✅ SECURE IMPLEMENTATIONS</h2>
                <p>These endpoints demonstrate proper security measures:</p>
                
                <ul>
                    <li><a href="/secure/reflected">Secure Reflected Input</a> - Proper sanitization</li>
                    <li><a href="/secure/stored">Secure Stored Comments</a> - XSS prevention</li>
                    <li><a href="/secure/calculator">Secure Calculator</a> - Safe expression evaluation</li>
                </ul>
            </div>
        </div>
    </body>
    </html>`);
});

app.listen(PORT, () => {
    console.log(`🚨 VULNERABLE server running on http://localhost:${PORT}`);
    console.log('⚠️  WARNING: This server contains intentional security vulnerabilities for educational purposes!');
});
