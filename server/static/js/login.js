/**
 * Pablo's Boson - Login Page JavaScript
 */

// Add focus animation
document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.form-control').forEach(input => {
        input.addEventListener('focus', () => {
            input.parentElement.style.boxShadow = '0 0 0 3px rgba(67, 97, 238, 0.3)';
        });
        
        input.addEventListener('blur', () => {
            input.parentElement.style.boxShadow = '0 4px 10px rgba(0,0,0,0.05)';
        });
    });
    
    // Add form validation
    const loginForm = document.querySelector('form');
    loginForm.addEventListener('submit', function(event) {
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value.trim();
        
        if (!username || !password) {
            event.preventDefault();
            
            // Create alert if it doesn't exist
            if (!document.querySelector('.alert')) {
                const alert = document.createElement('div');
                alert.className = 'alert alert-danger';
                alert.innerHTML = '<i class="fas fa-exclamation-triangle me-2"></i>Please enter both username and password.';
                
                const cardBody = document.querySelector('.card-body');
                cardBody.insertBefore(alert, cardBody.firstChild);
            }
        }
    });
    
    // Add animation to the login button
    const loginButton = document.querySelector('.btn-login');
    loginButton.addEventListener('mouseenter', function() {
        this.style.transform = 'translateY(-3px)';
        this.style.boxShadow = '0 8px 20px rgba(67, 97, 238, 0.4)';
    });
    
    loginButton.addEventListener('mouseleave', function() {
        this.style.transform = '';
        this.style.boxShadow = '';
    });
});