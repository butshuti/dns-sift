class WebPage(object):
    def __init__(self):
        pass     
    
    def getWebPage(self, graph_data):
        tpl = "var nodes = " + str(graph_data["nodes"]) + "; var edges = " + str(graph_data["edges"]) + ";"
        html = """
        <!doctype html>
        <head>
        <title> Session Profile Viz</title>
        <script src="visjs/vis.js"></script>
        <link type="text/css" rel="stylesheet" href="visjs/vis.css"/>
        <style type="text/css">
    #grapharea {
      width: 1900px;
      height: 1000px;
      border: 1px solid lightgray;
    }
  </style>
        </head>
        <body>
        <div id="grapharea"></div>
        <script type="text/javascript">
  var network;
  var allNodes;
  var highlightActive = false;
  """+tpl+"""
  var nodesDataset = new vis.DataSet(nodes); 
  var edgesDataset = new vis.DataSet(edges); 

  function redrawAll() {
    var container = document.getElementById('grapharea');
    var options = {
      nodes: {
        scaling: {
          min: 10,
          max: 30,
          label: {
            min: 8,
            max: 30,
            drawThreshold: 12,
            maxVisible: 20
          }
        },
        font: {
          size: 12,
          face: 'Tahoma'
        }
      },
      edges: {
        width: 0.15,
        color: {inherit: 'from'},
        smooth: {
          type: 'continuous'
        }
      },
      physics: false,
      interaction: {
        tooltipDelay: 200,
        hideEdgesOnDrag: true
      }
    };
    var data = {nodes:nodesDataset, edges:edgesDataset};


    network = new vis.Network(container, data, options);

    // get a JSON object
    allNodes = nodesDataset.get({returnType:"Object"});

    network.on("click",neighbourhoodHighlight);
  }

  function neighbourhoodHighlight(params) {
    // if something is selected:
    if (params.nodes.length > 0) {
      highlightActive = true;
      var i,j;
      var selectedNode = params.nodes[0];
      var degrees = 2;

      // mark all nodes as hard to read.
      for (var nodeId in allNodes) {
        allNodes[nodeId].color = 'rgba(200,200,200,0.5)';
        if (allNodes[nodeId].hiddenLabel === undefined) {
          allNodes[nodeId].hiddenLabel = allNodes[nodeId].label;
          allNodes[nodeId].label = undefined;
        }
      }
      var connectedNodes = network.getConnectedNodes(selectedNode);
      var allConnectedNodes = [];

      // get the second degree nodes
      for (i = 1; i < degrees; i++) {
        for (j = 0; j < connectedNodes.length; j++) {
          allConnectedNodes = allConnectedNodes.concat(network.getConnectedNodes(connectedNodes[j]));
        }
      }

      // all second degree nodes get a different color and their label back
      for (i = 0; i < allConnectedNodes.length; i++) {
        allNodes[allConnectedNodes[i]].color = 'rgba(150,150,150,0.75)';
        if (allNodes[allConnectedNodes[i]].hiddenLabel !== undefined) {
          allNodes[allConnectedNodes[i]].label = allNodes[allConnectedNodes[i]].hiddenLabel;
          allNodes[allConnectedNodes[i]].hiddenLabel = undefined;
        }
      }

      // all first degree nodes get their own color and their label back
      for (i = 0; i < connectedNodes.length; i++) {
        allNodes[connectedNodes[i]].color = undefined;
        if (allNodes[connectedNodes[i]].hiddenLabel !== undefined) {
          allNodes[connectedNodes[i]].label = allNodes[connectedNodes[i]].hiddenLabel;
          allNodes[connectedNodes[i]].hiddenLabel = undefined;
        }
      }

      // the main node gets its own color and its label back.
      allNodes[selectedNode].color = undefined;
      if (allNodes[selectedNode].hiddenLabel !== undefined) {
        allNodes[selectedNode].label = allNodes[selectedNode].hiddenLabel;
        allNodes[selectedNode].hiddenLabel = undefined;
      }
    }
    else if (highlightActive === true) {
      // reset all nodes
      for (var nodeId in allNodes) {
        allNodes[nodeId].color = undefined;
        if (allNodes[nodeId].hiddenLabel !== undefined) {
          allNodes[nodeId].label = allNodes[nodeId].hiddenLabel;
          allNodes[nodeId].hiddenLabel = undefined;
        }
      }
      highlightActive = false
    }

    // transform the object into an array
    var updateArray = [];
    for (nodeId in allNodes) {
      if (allNodes.hasOwnProperty(nodeId)) {
        updateArray.push(allNodes[nodeId]);
      }
    }
    nodesDataset.update(updateArray);
  }

  redrawAll()

</script>

        </body></html>
        """        
        return html