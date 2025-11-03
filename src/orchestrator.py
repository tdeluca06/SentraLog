import pprint
import detectors

from util.schema import Schema, DetectionResult
from preprocessing import preprocess
from detectors import Detector
from classification import Classifier


class ThreatDetector:
    """
    Orchestrates a set of detectors over grouped NGINX common access logs.

    Contains a list of detector instances and runs each detector against
    the given preprocessed logs. Output is returned in a dict keyed by
    detector name.
    """

    def __init__(self, logs: dict[str, list[Schema]]) -> None:
        self.logs: dict[str, list[Schema]] = logs
        self.detectors: list[Detector] = [
            detectors.BruteForceDetector(),
            detectors.SQLiDetector(),
            detectors.ScanDetector(),
        ]
        self.results: list[DetectionResult] = []

    def run(self) -> list[DetectionResult]:
        """
        Function to orchestrate all detectors over the given grouped NGINX
        access logs. Scans each log for potential malicious activity and
        returns a list of DetectionResults based off of the parsed activity.

        :return: a list of DetectionResult objects containing results
        """

        for d in self.detectors:
            matches = d.detect(self.logs)
            self.results.append(matches)

        return self.results


def detect() -> list[DetectionResult]:
    """
    Function to preprocess data and build the original list of DetectionResults without
    severity mapping.
    :return: a list of DetectionResults pre-classification
    """
    data: dict[str, list[Schema]] = preprocess()
    detector: ThreatDetector = ThreatDetector(data)

    return detector.run()


def classify(detections: list[DetectionResult]) -> list[DetectionResult]:
    """
    Function to classify severities of results.
    :param detections: a list of DetectionResults pre-classification
    :return: a list of labeled DetectionResults
    """
    classifier: Classifier = Classifier(detections)
    return classifier.classify()


if __name__ == "__main__":
    detection_list: list[DetectionResult] = detect()
    results = classify(detection_list)
    pprint.pprint(classify(detection_list), sort_dicts=False)
