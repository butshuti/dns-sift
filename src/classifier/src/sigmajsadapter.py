SIGMA_JS_CONTAINER_SOURCE_HEADER = """
<!doctype html>
<head>
<title> Session Profile Viz</title>
<style type="text/css">
  #sigma-container {
    max-width: 400px;
    height: 400px;
    margin: auto;
  }
</style>
</head>
<body>
<div id="sigma-container"></div>
<script src="sigma/sigma.min.js"></script>
<script>
  // Add a method to the graph model that returns an
  // object with every neighbors of a node inside:
  sigma.classes.graph.addMethod('neighbors', function(nodeId) {
    var k,
        neighbors = {},
        index = this.allNeighborsIndex[nodeId] || {};

    for (k in index)
      neighbors[k] = this.nodesIndex[k];

    return neighbors;
  });
  """
FOOTER = """
</script>
</body>
</html>
"""


class WebPage(object):
    def __init__(self):
        pass     
    
    def getWebPage(self, graph_data):
        tpl = "var s = new sigma({container:'sigma-container', graph:\"" + str(graph_data) + "\"}); s.refresh();"
        FAKE = """
        <!doctype html>
        <head>
        <title> Session Profile Viz</title>
        </head>
        <body>
        <!-- START SIGMA IMPORTS -->
        <script src="sigma_src/src/sigma.core.js"></script>
        <script src="sigma_src/src/conrad.js"></script>
        <script src="sigma_src/src/utils/sigma.utils.js"></script>
        <script src="sigma_src/src/utils/sigma.polyfills.js"></script>
        <script src="sigma_src/src/sigma.settings.js"></script>
        <script src="sigma_src/src/classes/sigma.classes.dispatcher.js"></script>
        <script src="sigma_src/src/classes/sigma.classes.configurable.js"></script>
        <script src="sigma_src/src/classes/sigma.classes.graph.js"></script>
        <script src="sigma_src/src/classes/sigma.classes.camera.js"></script>
        <script src="sigma_src/src/classes/sigma.classes.quad.js"></script>
        <script src="sigma_src/src/classes/sigma.classes.edgequad.js"></script>
        <script src="sigma_src/src/captors/sigma.captors.mouse.js"></script>
        <script src="sigma_src/src/captors/sigma.captors.touch.js"></script>
        <script src="sigma_src/src/renderers/sigma.renderers.canvas.js"></script>
        <script src="sigma_src/src/renderers/sigma.renderers.webgl.js"></script>
        <script src="sigma_src/src/renderers/sigma.renderers.svg.js"></script>
        <script src="sigma_src/src/renderers/sigma.renderers.def.js"></script>
        <script src="sigma_src/src/renderers/webgl/sigma.webgl.nodes.def.js"></script>
        <script src="sigma_src/src/renderers/webgl/sigma.webgl.nodes.fast.js"></script>
        <script src="sigma_src/src/renderers/webgl/sigma.webgl.edges.def.js"></script>
        <script src="sigma_src/src/renderers/webgl/sigma.webgl.edges.fast.js"></script>
        <script src="sigma_src/src/renderers/webgl/sigma.webgl.edges.arrow.js"></script>
        <script src="sigma_src/src/renderers/canvas/sigma.canvas.labels.def.js"></script>
        <script src="sigma_src/src/renderers/canvas/sigma.canvas.hovers.def.js"></script>
        <script src="sigma_src/src/renderers/canvas/sigma.canvas.nodes.def.js"></script>
        <script src="sigma_src/src/renderers/canvas/sigma.canvas.edges.def.js"></script>
        <script src="sigma_src/src/renderers/canvas/sigma.canvas.edges.arrow.js"></script>
        <script src="sigma_src/src/renderers/canvas/sigma.canvas.edges.curvedArrow.js"></script>
        <script src="sigma_src/src/renderers/canvas/sigma.canvas.extremities.def.js"></script>
        <script src="sigma_src/src/middlewares/sigma.middlewares.rescale.js"></script>
        <script src="sigma_src/src/middlewares/sigma.middlewares.copy.js"></script>
        <script src="sigma_src/src/misc/sigma.misc.animation.js"></script>
        <script src="sigma_src/src/misc/sigma.misc.bindEvents.js"></script>
        <script src="sigma_src/src/misc/sigma.misc.bindDOMEvents.js"></script>
        <script src="sigma_src/src/misc/sigma.misc.drawHovers.js"></script>
        <!-- END SIGMA IMPORTS -->
        <script src="sigma_src/plugins/sigma.plugins.animate/sigma.plugins.animate.js"></script>
        <script src="sigma_src/plugins/sigma.plugins.dragNodes/sigma.plugins.dragNodes.js"></script>
        <script src="sigma_src/plugins/sigma.plugins.relativeSize/sigma.plugins.relativeSize.js"></script>
        <div id="container">
          <style>
            #graph-container {
              top: 0;
              bottom: 0;
              left: 0;
              right: 0;
              position: absolute;
            }
          </style>
          <div id="graph-container"></div>
        </div>
        <script>
        /**
         * This example shows how to use the sigma.plugins.animate plugin. It
         * creates a random graph with two different views:
         *
         * The circular view displays the nodes on a circle, with each node
         * having a random color and a random size.
         *
         * The grid view displays every nodes with the same size, and on a grid.
         *
         * Every two seconds, the graph will be animated from a view to the other
         * one, in a one second animation.
         */
        var i,
            s,
            o,
            L = 10,
            N = 100,
            E = 500,
            g = """ + str(graph_data) + """,
            g2 = {
              nodes: [],
              edges: []
            },
            step = 0;
        
        // Instantiate sigma:
        s = new sigma({
          graph: g,
          container: 'graph-container',
          settings: {
            animationsTime: 1000
          }
        });
        
        setInterval(function() {
          var prefix = ['grid_', 'circular_'][step = +!step];
          sigma.plugins.animate(
            s,
            {
              x: prefix + 'x',
              y: prefix + 'y',
              size: prefix + 'size',
              color: prefix + 'color'
            }
          );
        }, 2000);
        </script>
        </body></html>
        """        
        html = SIGMA_JS_CONTAINER_SOURCE_HEADER + tpl + FOOTER
        return FAKE#html