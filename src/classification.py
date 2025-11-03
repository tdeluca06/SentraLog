import pprint

from util.schema import DetectionResult, Severity

THRESHOLDS = {
    "brute_force": (5, 7, 10),
    "sql_injection": (5, 7, 10),
    "scan_pattern": (5, 7, 10),
}


class Classifier:
    """
    Class to assign severity labels (low, medium, high) to each detection after
    orchestration.

    Severity classification is based off of the frequency of a rule violation from a
    specific IP using thresholding.
    """

    def __init__(self, detections: list[DetectionResult]) -> None:
        """
        Initialization of the classifier class.
        :param detections: a list of DetectionResults with severity defaulted to low
        """

        self.detections = detections
        self.results: list[DetectionResult] = []

    def classify(self) -> list[DetectionResult]:
        """
        Function to classify severity labels per entry by the amount of attempts.
        Thresholds are defined dynamically and can be changed based on need. The current
        implementation defines the thresholds as follows:

        For SQL Injections: Low = 5, Medium = 7, High = 10

        For Brute Force: Low = 5, Medium = 7, High = 10

        For Scanning Patterns: Low = 5, Medium = 7, High = 10

        :return:
        """

        LOW_THRESHOLD: int
        MEDIUM_THRESHOLD: int
        HIGH_THRESHOLD: int

        for detection in self.detections:
            freq: int = detection["freq"]
            if freq <= 0:
                continue

            thresholds = THRESHOLDS.get(detection["name"])
            if thresholds is None:
                print(f"Skipping unknown detection type {detection}")
                continue

            low_t, med_t, high_t = thresholds

            if freq >= high_t:
                detection["severity"] = Severity.HIGH
            elif freq >= med_t:
                detection["severity"] = Severity.MEDIUM

        return self.detections
