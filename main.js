// Utility functions
function showFeedback(message, type = 'info') {
    const feedbackContainer = document.querySelector('.feedback-container');
    const feedbackMessage = document.querySelector('#feedback-message');
    const nextButton = document.querySelector('#next-scenario');
    
    if (feedbackContainer && feedbackMessage) {
        feedbackContainer.classList.remove('d-none');
        feedbackMessage.innerHTML = message;
        feedbackMessage.className = `alert alert-${type}`;
        
        // Show the next scenario button
        if (nextButton) {
            nextButton.style.display = 'block';
        }
    }
}

function updateScore(score) {
    const scoreElement = document.querySelector('#current-score');
    if (scoreElement) {
        scoreElement.textContent = score;
    }
}

function updateDifficulty(difficulty) {
    const difficultyElement = document.querySelector('#current-difficulty');
    if (difficultyElement) {
        difficultyElement.textContent = difficulty;
    }
}

// Phishing Simulation Module
class PhishingSimulator {
    constructor() {
        this.currentScenario = null;
        this.score = 0;
        this.difficulty = 1;
        this.consecutiveCorrect = 0;
        this.isEvaluating = false;
    }

    async loadScenario() {
        try {
            // Disable the next button while loading
            const nextButton = document.querySelector('#next-scenario');
            if (nextButton) {
                nextButton.style.display = 'none';
            }
            
            // Hide the feedback container
            const feedbackContainer = document.querySelector('.feedback-container');
            if (feedbackContainer) {
                feedbackContainer.classList.add('d-none');
            }
            
            const response = await fetch(`/api/get-phishing-scenario?difficulty=${this.difficulty}`);
            const scenario = await response.json();
            this.currentScenario = scenario;
            
            // Update UI
            document.querySelector('#email-from').textContent = scenario.from;
            document.querySelector('#email-subject').textContent = scenario.subject;
            document.querySelector('#email-content').textContent = scenario.content;
            
            // Update difficulty display
            updateDifficulty(this.difficulty);
            
            // Add hover effects for email analysis
            this.addEmailAnalysisFeatures();
            
            // Enable response buttons
            this.setResponseButtonsState(true);
            
        } catch (error) {
            console.error('Error loading scenario:', error);
            showFeedback('Error loading scenario. Please try again.', 'danger');
        }
    }

    async evaluateResponse(response) {
        if (this.isEvaluating) return; // Prevent multiple submissions
        this.isEvaluating = true;
        
        try {
            // Disable response buttons while evaluating
            this.setResponseButtonsState(false);
            
            if (!this.currentScenario) {
                showFeedback('No scenario loaded. Please refresh the page.', 'danger');
                return;
            }

            const result = await fetch('/api/evaluate-phishing-response', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    scenario: this.currentScenario,
                    response: response
                })
            });
            
            if (!result.ok) {
                const errorData = await result.json();
                throw new Error(errorData.error || 'Server error');
            }

            const feedback = await result.json();
            
            if (feedback.error) {
                throw new Error(feedback.error);
            }
            
            if (feedback.correct) {
                this.score += 10;
                this.consecutiveCorrect++;
                
                // Show detailed feedback with learning points
                let feedbackHtml = `
                    <div class="feedback-content">
                        <h5 class="text-success mb-3"><i class="fas fa-check-circle"></i> Correct!</h5>
                        <p class="mb-2">${feedback.explanation}</p>
                        <h6 class="mt-3">Key Learning Points:</h6>
                        <ul class="list-group list-group-flush">
                            ${feedback.learning_points.map(point => `
                                <li class="list-group-item bg-transparent">
                                    <i class="fas fa-lightbulb text-warning"></i> ${point}
                                </li>
                            `).join('')}
                        </ul>
                    </div>
                `;
                
                showFeedback(feedbackHtml, 'success');
                
                // Increase difficulty after 3 consecutive correct answers
                if (this.consecutiveCorrect >= 3 && this.difficulty < 4) {
                    this.difficulty++;
                    this.consecutiveCorrect = 0;
                    showFeedback(`
                        <div class="level-up-message">
                            <h5><i class="fas fa-level-up-alt text-primary"></i> Level Up!</h5>
                            <p>Congratulations! You've advanced to level ${this.difficulty}.</p>
                            <p>Scenarios will be more challenging now.</p>
                        </div>
                    `, 'info');
                }
            } else {
                this.consecutiveCorrect = 0;
                let feedbackHtml = `
                    <div class="feedback-content">
                        <h5 class="text-danger mb-3"><i class="fas fa-times-circle"></i> Incorrect</h5>
                        <p class="mb-2">${feedback.explanation}</p>
                        <h6 class="mt-3">What to Watch For:</h6>
                        <ul class="list-group list-group-flush">
                            ${feedback.learning_points.map(point => `
                                <li class="list-group-item bg-transparent">
                                    <i class="fas fa-exclamation-circle text-warning"></i> ${point}
                                </li>
                            `).join('')}
                        </ul>
                    </div>
                `;
                showFeedback(feedbackHtml, 'danger');
            }
            
            updateScore(this.score);
            
        } catch (error) {
            console.error('Error evaluating response:', error);
            showFeedback(`Error: ${error.message}. Please try again.`, 'danger');
        } finally {
            this.isEvaluating = false;
        }
    }

    loadNextScenario() {
        this.loadScenario();
    }

    setResponseButtonsState(enabled) {
        const buttons = document.querySelectorAll('.response-buttons button');
        buttons.forEach(button => {
            button.disabled = !enabled;
            if (enabled) {
                button.classList.remove('opacity-50');
            } else {
                button.classList.add('opacity-50');
            }
        });
    }

    addEmailAnalysisFeatures() {
        const emailParts = document.querySelectorAll('.analyzable');
        emailParts.forEach(element => {
            element.style.cursor = 'pointer';
            element.setAttribute('data-tooltip', 'Click to analyze this part');
            element.onclick = () => {
                const type = element.id.replace('email-', '');
                this.analyzeEmailPart(type);
            };
        });
    }

    analyzeEmailPart(part) {
        if (!this.currentScenario) return;
        
        let analysis = '';
        const content = this.currentScenario[part];
        
        // Use the AI-provided indicators for analysis
        const relevantIndicators = this.currentScenario.indicators.filter(indicator => {
            return content.toLowerCase().includes(indicator.toLowerCase());
        });
        
        let analysisHtml = `
            <div class="analysis-content">
                <h5 class="mb-3"><i class="fas fa-search"></i> Analysis of ${part}</h5>
                ${relevantIndicators.length > 0 ? `
                    <div class="alert alert-warning">
                        <h6>Potential Indicators:</h6>
                        <ul class="mb-0">
                            ${relevantIndicators.map(indicator => `
                                <li>${indicator}</li>
                            `).join('')}
                        </ul>
                    </div>
                ` : `
                    <div class="alert alert-info">
                        No obvious indicators found in this section. 
                        Remember to analyze the full context.
                    </div>
                `}
            </div>
        `;
        
        showFeedback(analysisHtml, 'info');
    }
}

// Incident Response Module
class IncidentResponseGame {
    constructor() {
        this.currentScenario = null;
        this.score = 0;
    }

    async loadScenario() {
        try {
            const response = await fetch('/api/get-incident-scenario');
            const scenario = await response.json();
            this.currentScenario = scenario;
            
            // Update UI
            document.querySelector('#scenario-title').textContent = scenario.title;
            document.querySelector('#scenario-text').textContent = scenario.description;
            
            // Create option buttons
            const buttonContainer = document.querySelector('#action-buttons');
            buttonContainer.innerHTML = ''; // Clear previous buttons
            
            scenario.options.forEach(option => {
                const button = document.createElement('button');
                button.className = 'btn btn-outline-primary mb-2 w-100';
                button.textContent = option.text;
                button.onclick = () => this.evaluateResponse(option.id);
                buttonContainer.appendChild(button);
            });
        } catch (error) {
            console.error('Error loading scenario:', error);
            showFeedback('Error loading scenario. Please try again.', 'danger');
        }
    }

    async evaluateResponse(choiceId) {
        try {
            const result = await fetch('/api/evaluate-incident-response', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    scenario_id: this.currentScenario.id,
                    choice: choiceId
                })
            });
            
            const feedback = await result.json();
            
            if (feedback.correct) {
                this.score += 10;
                showFeedback(feedback.feedback, 'success');
            } else {
                showFeedback(feedback.feedback, 'danger');
            }
            
            updateScore(this.score);
            setTimeout(() => this.loadScenario(), 2000);
        } catch (error) {
            console.error('Error evaluating response:', error);
            showFeedback('Error evaluating response. Please try again.', 'danger');
        }
    }
}

// Training Module
class TrainingModule {
    constructor() {
        this.currentModule = null;
        this.currentLessonIndex = 0;
    }

    async loadModule(moduleId) {
        try {
            const response = await fetch(`/api/get-learning-module/${moduleId}`);
            const module = await response.json();
            this.currentModule = module;
            this.currentLessonIndex = 0;
            this.displayCurrentLesson();
        } catch (error) {
            console.error('Error loading module:', error);
            showFeedback('Error loading module. Please try again.', 'danger');
        }
    }

    displayCurrentLesson() {
        const lesson = this.currentModule.lessons[this.currentLessonIndex];
        const container = document.querySelector('.module-container');
        
        container.innerHTML = `
            <div class="lesson-content mb-4">
                <h3>${lesson.title}</h3>
                <p>${lesson.content}</p>
            </div>
            <div class="progress mb-4">
                <div class="progress-bar" style="width: ${(this.currentLessonIndex + 1) / this.currentModule.lessons.length * 100}%"></div>
            </div>
            <div class="navigation-buttons d-flex justify-content-between">
                ${this.currentLessonIndex > 0 ? 
                    '<button class="btn btn-secondary" onclick="trainingModule.previousLesson()">Previous</button>' : 
                    '<div></div>'}
                ${this.currentLessonIndex < this.currentModule.lessons.length - 1 ? 
                    '<button class="btn btn-primary" onclick="trainingModule.nextLesson()">Next</button>' : 
                    '<button class="btn btn-success" onclick="trainingModule.completeModule()">Complete</button>'}
            </div>
        `;
    }

    nextLesson() {
        if (this.currentLessonIndex < this.currentModule.lessons.length - 1) {
            this.currentLessonIndex++;
            this.displayCurrentLesson();
        }
    }

    previousLesson() {
        if (this.currentLessonIndex > 0) {
            this.currentLessonIndex--;
            this.displayCurrentLesson();
        }
    }

    completeModule() {
        showFeedback('Congratulations! You have completed this module.', 'success');
        // Add completion animation
        document.querySelector('.module-container').classList.add('module-completed');
    }
}

// Initialize modules when page loads
document.addEventListener('DOMContentLoaded', function() {
    // Initialize phishing simulator if we're on the phishing page
    if (document.querySelector('.email-container')) {
        window.phishingSimulator = new PhishingSimulator();
        phishingSimulator.loadScenario();
    }
    
    // Initialize incident response game if we're on the incident response page
    if (document.querySelector('.incident-container')) {
        window.incidentGame = new IncidentResponseGame();
        incidentGame.loadScenario();
    }
    
    // Initialize training module if we're on the training page
    if (document.querySelector('.module-container')) {
        window.trainingModule = new TrainingModule();
    }
});
