class SimpleModel:
    def __init__(self, centroids):
        self.centroids = centroids
        self.labels = sorted(centroids.keys())

    def predict_proba(self, feature_vectors):
        probs_all = []
        for vec in feature_vectors:
            distances = []
            for label in self.labels:
                centroid = self.centroids[label]
                dist = sum((a - b) ** 2 for a, b in zip(vec, centroid)) ** 0.5
                distances.append(dist)
            max_dist = max(distances) if distances else 1
            sims = [1 - (d / max_dist) for d in distances]
            total = sum(sims) or 1
            probs_all.append([s / total for s in sims])
        return probs_all