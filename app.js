const crypto = window.crypto || window.msCrypto;
const ADMIN_SECRET = 'beWise@'; // Store this securely in production

// Initialize users if not exists
let users = JSON.parse(localStorage.getItem('users') || '{}');

async function hashPassword(password) {
    try {
        const encoder = new TextEncoder();
        const data = encoder.encode(password);
        const hashBuffer = await crypto.subtle.digest('SHA-256', data);
        return Array.from(new Uint8Array(hashBuffer))
            .map(b => b.toString(16).padStart(2, '0'))
            .join('');
    } catch (error) {
        console.error('Hashing failed:', error);
        throw new Error('Password processing failed');
    }
}

async function signUp() {
    clearErrors();
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    const role = document.getElementById('role').value;
    const adminKey = document.getElementById('adminKey').value;

    try {
        // Validation
        if (!username || !password) {
            showError('Username and password are required');
            return;
        }

        if (role === 'admin' && adminKey !== ADMIN_SECRET) {
            showError('Invalid admin secret key', '#adminKey');
            return;
        }

        toggleLoading(true);
        
        if (users[username]) {
            showError('Username already exists');
            return;
        }

        const hashedPassword = await hashPassword(password);
        
        users[username] = {
            password: hashedPassword,
            role: role,
            students: [],
            createdAt: new Date().toISOString()
        };

        localStorage.setItem('users', JSON.stringify(users));
        logAction('signup', { role });
        showSuccess('Account created successfully!');
        document.getElementById('adminKey').value = '';
    } catch (error) {
        console.error('Registration error:', error);
        showError(error.message || 'Registration failed. Please try again.');
    } finally {
        toggleLoading(false);
    }
}

// Enhanced error handling functions
function showError(message, elementId = null) {
    const toast = Toastify({
        text: message,
        backgroundColor: '#e74c3c',
        duration: 3000,
        close: true,
        gravity: 'top',
        position: 'right'
    }).showToast();

    if (elementId) {
        const element = document.getElementById(elementId);
        element.classList.add('error');
        element.parentElement.querySelector('.error-message').style.display = 'block';
    }
}

function clearErrors() {
    document.querySelectorAll('.error').forEach(el => el.classList.remove('error'));
    document.querySelectorAll('.error-message').forEach(el => el.style.display = 'none');
}

function showSuccess(message) {
    Toastify({
        text: message,
        backgroundColor: '#27ae60',
        duration: 3000,
        close: true,
        gravity: 'top',
        position: 'right'
    }).showToast();
}

// Modified signIn function with better error handling
async function signIn() {
    clearErrors();
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();

    try {
        if (!username || !password) {
            showError('Username and password are required');
            return;
        }

        toggleLoading(true);
        const user = users[username];
        
        if (!user) {
            showError('Invalid credentials');
            return;
        }

        const hashedPassword = await hashPassword(password);
        
        if (user.password === hashedPassword) {
            // Successful login logic
        } else {
            showError('Invalid credentials');
        }
    } catch (error) {
        console.error('Login error:', error);
        showError('Authentication failed. Please try again.');
    } finally {
        toggleLoading(false);
    }
}
