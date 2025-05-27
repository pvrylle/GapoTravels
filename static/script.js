// Alert notifications
window.addEventListener('DOMContentLoaded', () => {
    const alerts = document.querySelectorAll('.alert-dismissible');
    alerts.forEach(alert => {
    setTimeout(() => {
        // Bootstrap 5 uses the Alert class to handle dismissals
        const bsAlert = bootstrap.Alert.getOrCreateInstance(alert);
        bsAlert.close();
    }, 1300); // 1300 milliseconds = 1.3 seconds
});
});

// Profile image preview functionality
function previewImage(input) {
if (input.files && input.files[0]) {
    // Check file size - 5MB maximum
    if (input.files[0].size > 5 * 1024 * 1024) {
        alert('File is too large! Maximum size is 5MB.');
        input.value = '';
        return;
    }
    
    // Check file extension
    const fileName = input.files[0].name;
    const fileExt = fileName.split('.').pop().toLowerCase();
    const allowedExts = ['png', 'jpg', 'jpeg', 'gif'];
    
    if (!allowedExts.includes(fileExt)) {
        alert('Invalid file type! Please upload PNG, JPG, JPEG or GIF files only.');
        input.value = '';
        return;
    }
    
    const reader = new FileReader();
    reader.onload = function(e) {
        // Remove the icon and create an image element when a file is selected
        const profilePreview = document.querySelector('.profile-preview');
        const iconWrapper = document.querySelector('.profile-icon-wrapper');
        
        if (iconWrapper) {
            iconWrapper.remove();
            
            const img = document.createElement('img');
            img.src = e.target.result;
            img.style.width = '100%';
            img.style.height = '100%';
            img.style.objectFit = 'cover';
            
            profilePreview.insertBefore(img, profilePreview.firstChild);
        } else {
            // If there's already an image, just update its source
            const img = profilePreview.querySelector('img');
            if (img) img.src = e.target.result;
        }
    };
    reader.readAsDataURL(input.files[0]);
}
}

// Toggle password visibility based on eye icon state
function togglePassword(inputId, toggleIcon) {
    const input = document.getElementById(inputId);
    const icon = toggleIcon.querySelector('i');

    if (icon.classList.contains('fa-eye')) {
        // Show password
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
    } else {
        // Hide password
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    }
}

// Add form validation
document.addEventListener('DOMContentLoaded', function() {
const signupForm = document.getElementById('signupForm');
if (signupForm) {
    // Check privacy checkbox when 'I Understand' is clicked in the privacy modal
    const privacyAgreeBtn = document.getElementById('privacyAgreeBtn');
    if (privacyAgreeBtn) {
        privacyAgreeBtn.addEventListener('click', function() {
            const privacyCheckbox = document.getElementById('privacy_agreement');
            if (privacyCheckbox) {
                privacyCheckbox.checked = true;
                privacyCheckbox.classList.remove('is-invalid');
                const privacyError = document.getElementById('privacy-error');
                if (privacyError) {
                    privacyError.style.display = 'none';
                }
            }
        });
    }
    
    signupForm.addEventListener('submit', function(event) {
        const privacyCheckbox = document.getElementById('privacy_agreement');
        const privacyError = document.getElementById('privacy-error');
        
        if (!privacyCheckbox.checked) {
            event.preventDefault();
            privacyCheckbox.classList.add('is-invalid');
            privacyError.style.display = 'block';
            return false;
        } else {
            privacyCheckbox.classList.remove('is-invalid');
            privacyError.style.display = 'none';
        }
    });

    // Clear error state when checkbox is checked
    document.getElementById('privacy_agreement').addEventListener('change', function() {
        if (this.checked) {
            this.classList.remove('is-invalid');
            document.getElementById('privacy-error').style.display = 'none';
        }
    });
}
});

// Review modal functionality
function showReviewModal(destinationName) {
// Set the destination in the hidden input
document.getElementById('reviewDestination').value = destinationName;
// Display the destination in the modal body
document.getElementById('modalDestination').textContent = destinationName;
new bootstrap.Modal(document.getElementById('reviewModal')).show();
}

// Star rating functionality
document.addEventListener('DOMContentLoaded', function() {
const stars = document.querySelectorAll('#starRating .star');
const ratingInput = document.getElementById('rating');

if (stars.length > 0 && ratingInput) {
    stars.forEach((star, index) => {
        star.addEventListener('click', () => {
            const selectedValue = parseInt(star.getAttribute('data-value'));
            ratingInput.value = selectedValue;
    
            // Clear all
            stars.forEach(s => s.classList.remove('selected'));
    
            // Set selected from left to right
            for (let i = 0; i < selectedValue; i++) {
                stars[i].classList.add('selected');
            }
        });
    });
}
});

//Explore categories for the Reviews
const stars = document.querySelectorAll('#starRating .star');
const ratingInput = document.getElementById('rating');

stars.forEach((star, index) => {
star.addEventListener('click', () => {
    const selectedValue = parseInt(star.getAttribute('data-value'));
    ratingInput.value = selectedValue;

    // Clear all
    stars.forEach(s => s.classList.remove('selected'));

    // Set selected from left to right
    for (let i = 0; i < selectedValue; i++) {
        stars[i].classList.add('selected');
    }
});
});

// All reviews data will be stored globally
let allReviews = [];
let currentBatchIndex = 0;
let rotationInterval;
let reviewsPerBatch = window.innerWidth <= 768 ? 2 : 8;
window.addEventListener('resize', () => {
    reviewsPerBatch = window.innerWidth <= 768 ? 2 : 8;
});

// Function to fetch and display reviews
function fetchReviews() {
    // Show loader before fetching
    const loader = document.getElementById('reviews-loader');
    if (loader) loader.style.display = 'block';
    const reviewsContainer = document.getElementById('reviews-container');
    if (reviewsContainer) reviewsContainer.innerHTML = '';

    fetch('/get_reviews')
        .then(response => response.json())
        .then(reviews => {
            // Hide loader after fetching
            if (loader) loader.style.display = 'none';
            allReviews = reviews;
            const reviewsContainer = document.getElementById('reviews-container');
            
            if (reviews.length === 0) {
                // Apply container styling for no reviews
                reviewsContainer.style.display = 'flex';
                reviewsContainer.style.justifyContent = 'center';
                reviewsContainer.style.alignItems = 'center';
                reviewsContainer.style.minHeight = '150px';
                
                reviewsContainer.innerHTML = '<p class="text-center text-muted" style="margin-top: 30px; margin-bottom: 30px;">No reviews yet. Be the first to write a review!</p>';
                return;
            } else {
                // Reset container styling if there are reviews
                reviewsContainer.style = '';
                // Start auto-rotation only if we have more than reviewsPerBatch reviews
                displayCurrentBatch();
                
                // Clear any existing interval before setting a new one
                if (rotationInterval) {
                    clearInterval(rotationInterval);
                }
                
                // Only set up auto-rotation if we have more than reviewsPerBatch reviews
                if (allReviews.length > reviewsPerBatch) {
                    rotationInterval = setInterval(rotateReviews, 5000); // 5 seconds rotation
                }
            }
        })
        .catch(error => {
            if (loader) loader.style.display = 'none';
            console.error('Error fetching reviews:', error);
            document.getElementById('reviews-container').innerHTML = 
                '<p class="text-danger">Error loading reviews. Please try again later.</p>';
        });
}

// Function to display the current batch of reviews
function displayCurrentBatch() {
    const reviewsContainer = document.getElementById('reviews-container');
    const startIndex = currentBatchIndex * reviewsPerBatch;
    const endIndex = Math.min(startIndex + reviewsPerBatch, allReviews.length);
    const currentBatch = allReviews.slice(startIndex, endIndex);
    
    // Create a wrapper for the fade effect
    const reviewsHTML = currentBatch.map((review, index) => `
        <div class="review-card" data-index="${startIndex + index}">
            <div class="review-header">
                <img src="${review.users.profile_pic || '/static/images/default-avatar.jpg'}" 
                     alt="${review.users.first_name} ${review.users.last_name}" 
                     onerror="this.src='/static/images/default-avatar.jpg'">
                <div class="review-meta">
                    <h5>${review.users.first_name} ${review.users.last_name}</h5>
                    <small>${new Date(review.created_at).toLocaleDateString('en-US', {
                        year: 'numeric',
                        month: 'long',
                        day: 'numeric'
                    })}</small>
                </div>
            </div>
            <div class="rating">
                ${'★'.repeat(review.rating)}${'☆'.repeat(5 - review.rating)}
            </div>
            <div class="review-content">
                <div class="review-text-container">
                    <p class="review-text">${review.content}</p>
                </div>
                <button class="see-more-btn" 
                        data-author="${review.users.first_name} ${review.users.last_name}" 
                        data-date="${new Date(review.created_at).toLocaleDateString('en-US', {
                            year: 'numeric',
                            month: 'long',
                            day: 'numeric'
                        })}" 
                        data-avatar="${review.users.profile_pic || '/static/images/default-avatar.jpg'}"
                        data-rating="${review.rating}"
                        data-destination="${review.destination}"
                        data-content="${review.content.replace(/"/g, '&quot;')}">See more</button>
            </div>
            <div class="review-footer">
                <span class="review-destination">
                    <i class="fas fa-map-marker-alt"></i>
                    ${review.destination}
                </span>
                ${review.user_id === currentUserId ? 
                    `<button onclick="showDeleteConfirmation('${review.id}')" 
                             class="btn btn-sm btn-danger">
                        <i class="fas fa-trash"></i>
                     </button>` : ''}
            </div>
        </div>
    `).join('');

    // Update the DOM with fade effect
    reviewsContainer.classList.add('fade-out');
    
    setTimeout(() => {
        reviewsContainer.innerHTML = reviewsHTML;
        
        // Initialize animations for new cards
        const cards = reviewsContainer.querySelectorAll('.review-card');
        cards.forEach((card, index) => {
            card.style.animationDelay = `${index * 0.1}s`;
        });
        
        // Handle "See More" functionality
        setupSeeMoreButtons();
        
        // Fade back in
        reviewsContainer.classList.remove('fade-out');
        reviewsContainer.classList.add('fade-in');
        
        setTimeout(() => {
            reviewsContainer.classList.remove('fade-in');
        }, 500);
    }, 500);
}

// Function to rotate to the next batch of reviews
function rotateReviews() {
    const totalBatches = Math.ceil(allReviews.length / reviewsPerBatch);
    currentBatchIndex = (currentBatchIndex + 1) % totalBatches; // Loop back to first batch after last
    displayCurrentBatch();
}

// Toggle custom destination input
const destinationSelect = document.getElementById('destinationSelect');
if (destinationSelect) {
    destinationSelect.addEventListener('change', function() {
        const customInput = document.getElementById('customDestination');
        if (customInput) {
            if (this.value === 'custom') {
                customInput.style.display = 'block';
                customInput.required = true;
            } else {
                customInput.style.display = 'none';
                customInput.required = false;
            }
        }
    });
}

// Show delete confirmation modal
function showDeleteConfirmation(reviewId) {
const modal = new bootstrap.Modal(document.getElementById('deleteConfirmModal'));
const form = document.getElementById('deleteReviewForm');
form.action = `/delete_review/${reviewId}`;
modal.show();
}

// Setup See More buttons for review cards
function setupSeeMoreButtons() {
    const reviewContainers = document.querySelectorAll('.review-text-container');
    const seeMoreButtons = document.querySelectorAll('.see-more-btn');
    
    reviewContainers.forEach((container, index) => {
        const button = seeMoreButtons[index];
        const content = container.querySelector('.review-text');
        
        // Check if content is taller than container
        if (content.scrollHeight > container.clientHeight) {
            button.style.display = 'block';
            
            button.addEventListener('click', function() {
                // Open the modal with full review details
                openReviewModal(this);
            });
        } else {
            button.style.display = 'none';
        }
    });
}

// Function to open the review modal
function openReviewModal(button) {
    // Get review details from data attributes
    const author = button.getAttribute('data-author');
    const date = button.getAttribute('data-date');
    const avatar = button.getAttribute('data-avatar');
    const rating = button.getAttribute('data-rating');
    const destination = button.getAttribute('data-destination');
    const content = button.getAttribute('data-content');
    
    // Set modal content
    document.getElementById('modalReviewAuthor').textContent = author;
    document.getElementById('modalReviewDate').textContent = date;
    document.getElementById('modalReviewAvatar').src = avatar;
    document.getElementById('modalReviewAvatar').onerror = function() {
        this.src = '/static/images/default-avatar.jpg';
    };
    document.getElementById('modalReviewRating').innerHTML = '★'.repeat(rating) + '☆'.repeat(5 - rating);
    document.getElementById('modalReviewDestination').textContent = destination;
    document.getElementById('modalReviewContent').textContent = content;
    
    // Open the modal
    const modal = new bootstrap.Modal(document.getElementById('fullReviewModal'));
    modal.show();
}