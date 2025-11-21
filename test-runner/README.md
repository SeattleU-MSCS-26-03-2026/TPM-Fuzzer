# Test Data

## Running Tests

1. Start the Docker Compose environment as described in the main README:
```sh
docker compose up -d
```

2. Run the test runner with the corpus and crash test data:
```sh
python3 test_runner.py --corpus corpus --crashes crashes
```
