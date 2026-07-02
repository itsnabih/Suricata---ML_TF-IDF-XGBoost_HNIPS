import pickle
import xgboost as xgb
with open('xgb_sqli_model.pkl', 'rb') as f:
    model = pickle.load(f)
with open('tfidf_vectorizer.pkl', 'rb') as f:
    vec = pickle.load(f)
with open('feature_selector.pkl', 'rb') as f:
    sel = pickle.load(f)

test_payload = "1"
tfidf_features = vec.transform([test_payload])
selected = sel.transform(tfidf_features)
import scipy.sparse
if scipy.sparse.issparse(selected):
    X = selected.toarray()
else:
    X = selected
pred = model.predict_proba(X)[0][1]
print(f"Payload: '{test_payload}', Proba: {pred}")
