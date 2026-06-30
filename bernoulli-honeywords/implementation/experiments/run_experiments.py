from matplotlib import pyplot as plt

import experiments.amnesia_local_experiments, experiments.honeychecker_experiments
import utils
import heapq

'''
Plot the tdp experiments for both systems.
'''
def plot_tdp(results_h, n_values_h, N_h, results_a):
    fig, axes = plt.subplots(1, 2, figsize=(13, 5), sharey=True)
    fig.suptitle("TDP vs n/N", fontsize=13)
 
    x_vals = [n / N_h for n in n_values_h]
 
    configs = [("p_h=1e-2", "p_h = 1e-2"), ("p_h=1e-4", "p_h = 1e-4")]
 
    for ax, (label, title) in zip(axes, configs):
        data_h = results_h[label]
        data_a = results_a[label]
        
        ax.plot(x_vals, data_h["tdp"], linewidth=2, label="Honeychecker")
        ax.plot(x_vals, data_a["tdp"], linewidth=2, label="Amnesia local")
 
        ax.axhline(y=0.5, color='gray', linestyle='--', alpha=0.5, label='tdp = 0.5')
 
        ax.set_title(title)
        ax.set_xlabel("Fraction of accounts attacked (n/N)")
        ax.set_ylabel("True Detection Probability tdp(n)")
        ax.set_xlim(0, 0.5)
        ax.set_ylim(0, 1.05)
        ax.legend(fontsize=9)
        ax.grid(True, alpha=0.3)
 
    plt.tight_layout()
    plt.savefig("output/tdp_curves.png", dpi=150)
    plt.show()

'''
Plot the success vs alarm experiments for both systems.
'''
def plot_success_comparison(hc_curve, amnesia_curve):
    (x_hc, y_hc) = hc_curve
    (x_am, y_am) = amnesia_curve

    plt.figure(figsize=(9, 5))
    plt.plot(x_hc, y_hc, label='Honeychecker', linewidth=2)
    plt.plot(x_am, y_am, label='Amnesia', linewidth=2)
    plt.xlabel('Accounts detected (honeyword entered) (x)')
    plt.ylabel('Real passwords silently found (y)')
    plt.title('Success vs. Alarm: Honeychecker vs Amnesia')
    plt.legend()
    plt.tight_layout()
    plt.savefig('output/success_comparison.png', dpi=150)
    plt.show()

if __name__ == "__main__":
    data_weighted, counts = utils.load_weighted_data("data/hashmob_counts.txt")
    top_idx = heapq.nlargest(100000, range(len(counts)), key=lambda i: counts[i])
    ranking = [data_weighted[i] for i in top_idx]
    ranking_counts = [counts[i] for i in top_idx]

    results_h, n_values_h, N_h, hc_curves = experiments.honeychecker_experiments.run_simulation(ranking, ranking_counts)
    results_a, n_values_a, N_a, a_curves = experiments.amnesia_local_experiments.run_simulation(ranking, ranking_counts)
    plot_tdp(results_h, n_values_h, N_h, results_a)
    plot_success_comparison(hc_curves, a_curves)
    