import pymysql
from faker import Faker
import random

# Connect to MySQL
conn = pymysql.connect(
    host="127.0.0.1",
    user="root",
    password="W!f4vas2CX.TKLy",
    database="teamproject"
)
cursor = conn.cursor()
# Create a Faker instance
fake = Faker()

# Additional health history entries
health_histories = [
    "No significant health issues",
    "History of allergies",
    "High blood pressure",
    "Diabetes",
    "Asthma",
    "Heart disease",
    "Low iron levels",
    "History of migraines",
    "Joint pain",
    "Arthritis",
    "Thyroid issues",
    "Depression",
    "Anxiety disorder",
    "Gastrointestinal issues",
    "Chronic back pain",
    "Sleep apnea",
    "Allergic to certain medications",
    "History of fractures",
    "Kidney stones",
    "Liver disease",
    "History of cancer",
    "Osteoporosis",
    "Vision problems",
    "Hearing loss",
    "Chronic fatigue syndrome",
    "Autoimmune disorder",
    "Eating disorder",
    "History of surgeries",
    "Lung disease",
    "Skin conditions (eczema, psoriasis)",
    "Allergic to specific foods",
    "History of concussions",
    "Dental issues",
    "Blood clotting disorder",
    "Chronic headaches",
    "Reproductive health issues",
    "Substance abuse history",
    "Physical disabilities",
    "Chronic infections",
    "Neurological disorders",
    "History of seizures",
    "Speech or language disorders",
    "Chronic pain syndrome",
    "Thrombosis",
    "Genetic conditions",
    "History of hospitalizations",
    "Autoimmune skin disorders",
    "Digestive disorders",
    "Chronic respiratory conditions",
    "History of strokes",
    "Chronic kidney disease",
    "Immune deficiencies",
    "Blood disorders",
    "History of mental health treatment",
    "Developmental disorders",
    "Chronic inflammatory conditions",
    "History of dental surgeries",
    "Rehabilitation history",
    "Balance disorders",
    "Chronic infections",
    "History of joint replacements",
    "Chronic skin infections",
    "Gynecological health issues",
    "Chronic eye conditions",
    "History of eye surgeries",
    "Chronic sinusitis",
    "Gastrointestinal disorders",
    "Inflammatory bowel disease",
    "Chronic liver disease",
    "Chronic pancreatitis",
    "Chronic kidney infections",
    "Chronic urinary tract infections",
    "Chronic sinus infections",
    "Chronic ear infections",
    "Chronic pain conditions",
    "Chronic neurological conditions",
    "Chronic autoimmune conditions",
    "Chronic digestive conditions",
    "Chronic endocrine conditions",
    "Chronic musculoskeletal conditions",
    "Chronic cardiovascular conditions",
    "Chronic respiratory conditions",
    "Chronic renal conditions",
    "Chronic reproductive conditions",
    "Chronic hematologic conditions",
    "Chronic psychiatric conditions",
    "Chronic dermatologic conditions",
    "Chronic infectious conditions",
    "Chronic metabolic conditions",
    "Chronic immunologic conditions",
    "Chronic genitourinary conditions",
    "Chronic ophthalmologic conditions",
    "Chronic otologic conditions",
    "Chronic gustatory conditions",
    "Chronic olfactory conditions",
    "Chronic somatosensory conditions",
    "Chronic vestibular conditions",
    "Chronic proprioceptive conditions",
    "Chronic neuromotor conditions",
    "Chronic respiratory conditions",
    "Chronic gastrointestinal conditions",
    "Chronic renal conditions",
    "Chronic hepatobiliary conditions",
    "Chronic endocrine conditions",
    "Chronic reproductive conditions",
    "Chronic hematologic conditions",
    "Chronic immunologic conditions",
    "Chronic dermatologic conditions",
    "Chronic metabolic conditions",
    "Chronic musculoskeletal conditions",
    "Chronic psychiatric conditions",
    "Chronic infectious conditions",
    "Chronic cardiovascular conditions",
    "Chronic neurological conditions",
    "Chronic respiratory conditions",
    "Chronic genitourinary conditions",
    "Chronic gastrointestinal conditions",
    "Chronic hepatobiliary conditions",
    "Chronic endocrine conditions",
    "Chronic reproductive conditions",
    "Chronic hematologic conditions",
    "Chronic immunologic conditions",
    "Chronic dermatologic conditions",
    "Chronic metabolic conditions",
    "Chronic musculoskeletal conditions",
    "Chronic psychiatric conditions",
    "Chronic infectious conditions",
    "Chronic cardiovascular conditions",
    "Chronic neurological conditions",
    "Chronic respiratory conditions",
    "Chronic genitourinary conditions",
    "Chronic gastrointestinal conditions",
    "Chronic hepatobiliary conditions",
    "Chronic endocrine conditions",
    "Chronic reproductive conditions",
    "Chronic hematologic conditions",
    "Chronic immunologic conditions",
    "Chronic dermatologic conditions",
    "Chronic metabolic conditions",
    "Chronic musculoskeletal conditions",
    "Chronic psychiatric conditions",
    "Chronic infectious conditions",
    "Chronic cardiovascular conditions",
    "Chronic neurological"]
# Generate and insert 100 random entries with health_history
for _ in range(100):
    first_name = fake.first_name()
    last_name = fake.last_name()
    gender = random.choice([0, 1])
    age = random.randint(18, 60)
    weight = round(random.uniform(50.0, 100.0), 2)
    height = round(random.uniform(150.0, 190.0), 2)
    health_history = random.choice(health_histories)

    # Insert data into the database
    cursor.execute("""
        INSERT INTO person_data (first_name, last_name, gender, age, weight, height, health_history)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (first_name, last_name, gender, age, weight, height, health_history))

# Commit changes and close the connection
conn.commit()
conn.close()