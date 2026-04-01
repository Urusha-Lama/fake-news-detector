import pandas as pd
import pickle
import re

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import PassiveAggressiveClassifier

# Load datasets
fake = pd.read_csv("Fake.csv")
real = pd.read_csv("True.csv")

# Add labels
fake["label"] = 0
real["label"] = 1

# Keep only needed columns
fake = fake[['text','label']]
real = real[['text','label']]

# Combine
data = pd.concat([fake, real])

# Clean text
def clean_text(text):
    text = re.sub(r'[^a-zA-Z]', ' ', str(text))
    text = text.lower()
    return text

data['text'] = data['text'].apply(clean_text)

# Split
X = data['text']
y = data['label']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

# Vectorize
tfidf = TfidfVectorizer(max_features=5000)
X_train_vect = tfidf.fit_transform(X_train)

# Train model
model = PassiveAggressiveClassifier(max_iter=1000)
model.fit(X_train_vect, y_train)

# Save
pickle.dump(model, open("model.pkl","wb"))
pickle.dump(tfidf, open("vectorizer.pkl","wb"))

print("✅ DONE")