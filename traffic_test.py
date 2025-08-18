import requests
import random
import time
import threading
import uuid
import argparse

# --- Configuration ---
BASE_URL = "http://127.0.0.1:5000"
PROJECTS = [
    'catherine', 'george', 'lydia', 'mike_kris', 'nata', 
    'poki', 'kamyar', 'aurelie'
]
SAMPLE_COMMENTS = [
    "This is truly thought-provoking.",
    "I'm not sure I understand, but it's beautiful.",
    "The connection between technology and art is fascinating.",
    "This piece challenges my perceptions.",
    "A very powerful and moving installation.",
    "I feel a sense of wonder.",
    "It makes me think about the future in a new way.",
    "The use of AI is both brilliant and a little unsettling.",
    "I could spend hours with this.",
    "An incredible fusion of ideas."
]

def simulate_user(user_id):
    """Simulates a single user's interaction with the application."""
    visitor_id = str(uuid.uuid4())
    project = random.choice(PROJECTS)
    
    print(f"[User {user_id}] Starting journey. Visitor ID: {visitor_id}, Project: {project}")

    try:
        # 1. Simulate visiting a project page
        visit_payload = {
            'project': project,
            'visitor_id': visitor_id
        }
        visit_res = requests.post(f"{BASE_URL}/visit", json=visit_payload, timeout=10)
        
        if visit_res.status_code == 200:
            print(f"[User {user_id}] Successfully registered visit for project '{project}'.")
        else:
            print(f"[User {user_id}] Failed to register visit. Status: {visit_res.status_code}, Response: {visit_res.text}")
            return # Stop if visit fails

        # Wait for a random time, simulating user engagement
        time.sleep(random.uniform(2, 8))

        # 2. Simulate leaving feedback
        comment = random.choice(SAMPLE_COMMENTS) + f" ({random.randint(1, 1000)})" # Add random number to ensure uniqueness
        feedback_payload = {
            'project': project,
            'visitor_id': visitor_id,
            'content': comment
        }
        feedback_res = requests.post(f"{BASE_URL}/feedback", json=feedback_payload, timeout=10)
        
        if feedback_res.status_code == 200:
            print(f"[User {user_id}] Successfully submitted feedback: '{comment}'")
        else:
            print(f"[User {user_id}] Failed to submit feedback. Status: {feedback_res.status_code}, Response: {feedback_res.text}")

    except requests.exceptions.RequestException as e:
        print(f"[User {user_id}] An error occurred: {e}")

def main():
    parser = argparse.ArgumentParser(description="Simulate user traffic for the Machinic Encounters application.")
    parser.add_argument("-u", "--users", type=int, default=10, help="Number of concurrent users to simulate.")
    parser.add_argument("-r", "--runs", type=int, default=1, help="Number of times each user will run through the simulation.")
    parser.add_argument("-d", "--delay", type=float, default=1.0, help="Delay in seconds between starting each user thread.")
    args = parser.parse_args()

    print(f"Starting traffic simulation with {args.users} users, running {args.runs} times each.")
    
    threads = []
    
    for run in range(args.runs):
        print(f"\n--- Starting Run {run + 1}/{args.runs} ---")
        for i in range(args.users):
            thread_id = (run * args.users) + i
            thread = threading.Thread(target=simulate_user, args=(thread_id,))
            threads.append(thread)
            thread.start()
            time.sleep(args.delay) # Stagger thread starts to be more realistic

        # Wait for all threads in the current run to complete
        for thread in threads:
            thread.join()
        
        threads = [] # Reset for next run
        if run < args.runs - 1:
            print(f"--- Run {run + 1} complete. Waiting 5 seconds before next run. ---")
            time.sleep(5)
            
    print("\nTraffic simulation finished.")

if __name__ == "__main__":
    main()
