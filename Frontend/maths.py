import matplotlib.pyplot as plt
import networkx as nx
import sympy as sp

G = nx.Graph()

G.add_nodes_from([1, 2, 3, 4, 5])
G.add_edges_from([(1, 2), (2, 3), (3, 4), (4, 5)])

is_planar, _ = nx.check_planarity(G)

colors = nx.coloring.greedy_color(G, strategy="DSATUR")

print("Is Planar:", is_planar)
print("Chromatic Number:", len(set(colors.values())))

P = nx.algorithms.polynomials.chromatic_polynomial(G)
P_lam = sp.factor(P.subs(sp.Symbol("x"), sp.Symbol("λ")))

print("Chromatic Polynomial:", P_lam)

pos = nx.planar_layout(G) if is_planar else nx.kamada_kawai_layout(G)

nx.draw(
    G,
    pos=pos,
    with_labels=True,
    node_color=list(colors.values()),
    cmap=plt.cm.tab10,
    node_size=800
)

plt.show()