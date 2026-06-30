import matplotlib.pyplot as plt
import math

def plot_experiment_1(results):
    p_h_vals = [r[0] for r in results]
    fdp_depth = [r[1] for r in results]
    fdp_breadth = [r[2] for r in results]
    x_labels = [f"10^{int(round(math.log10(p)))}" for p in p_h_vals]

    plt.figure(figsize=(9, 5))
    plt.plot(x_labels, fdp_depth, marker='o', label='fdp(10^6, 10) — depth-first')
    plt.plot(x_labels, fdp_breadth, marker='s', label='fdp(10^4, 1000) — breadth-first')
    plt.axhline(y=0.1, color='red', linestyle='--', label='ε = 0.1 bound')
    plt.xlabel('p_h')
    plt.ylabel('False Detection Probability')
    plt.title('FDP vs p_h')
    plt.legend()
    plt.tight_layout()
    plt.savefig('output/exp1_fdp.png', dpi=150)
    plt.show()

def plot_experiment_2(results):
    observed = [r[0] for r in results]
    expected = [r[1] for r in results]

    plt.figure(figsize=(6, 6))
    plt.plot(expected, observed, 'bo', markersize=8, label='Observed hit rate')
    plt.plot([0, 1], [0, 1], 'r--', label='y = x (perfect)')
    plt.xlabel('Configured p_h')
    plt.ylabel('Observed hit rate')
    plt.title('Observed vs Expected p_h')
    plt.legend()
    plt.tight_layout()
    plt.savefig('output/exp2_bloom_validation.png', dpi=150)
    plt.show()

def plot_experiment_3(results, n_values, N):
    fig, axes = plt.subplots(1, 2, figsize=(13, 5), sharey=True)
    fig.suptitle("TDP vs n/N - Honeychecker", fontsize=13)
 
    x_vals = [n / N for n in n_values]
 
    configs = [("p_h=1e-2", "p_h = 1e-2"),("p_h=1e-4", "p_h = 1e-4")]
 
    for ax, (label, title) in zip(axes, configs):
        data = results[label]
        ax.plot(x_vals, data["tdp"], marker='o', linewidth=2)
 
        ax.axhline(y=0.5, color='gray', linestyle='--', alpha=0.5, label='tdp = 0.5')
 
        ax.set_title(title)
        ax.set_xlabel("Fraction of accounts attacked (n/N)")
        ax.set_ylabel("True Detection Probability tdp(n)")
        ax.set_xlim(0, 0.5)
        ax.set_ylim(0, 1.05)
        ax.legend(fontsize=9)
        ax.grid(True, alpha=0.3)
 
    plt.tight_layout()
    plt.savefig("output/exp3_tdp_curves.png", dpi=150)
    plt.show()
 
def plot_experiment_4(results):
    (x, y) = results

    plt.figure(figsize=(9, 5))
    plt.plot(x, y, label='Passwords', linewidth=2, drawstyle='default')
    plt.xlabel('Total honeyword login attempts (x)')
    plt.ylabel('Real passwords successfully found (y)')
    plt.title('Success vs. Alarm Graph - Honeychecker')
    plt.legend()
    plt.tight_layout()
    plt.savefig('output/exp4_success_number_hc.png', dpi=150)
    plt.show()