install:
	python -m pip install -r requirements.txt

test:
	python -m pytest -q

run:
	python -m streamlit run app.py

cloudtrail-demo:
	python cloudtrail_detector.py --file data/cloudtrail/sample_cloudtrail_iam_events.json

github-context:
	python -m src.github_repo_context srkyn/IdentityRiskGraph
