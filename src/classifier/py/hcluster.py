"""
An implementation of Hierarchical Clustering, 
code from J.E. Solem, "Computer Vision with Python", ch.6.
"""
from itertools import combinations
from numpy import array, sqrt
from PIL import Image,ImageDraw, ImageFont

class ClusterNode(object):
    def __init__(self, vec, left, right, distance=0.0, count=1):
        self.left = left
        self.right = right
        self.vec = array(vec)
        self.distance = distance
        self.count = count #only used for weighted average
        
    def extract_clusters(self, dist):
        """Extract list of sub-tree clusters from 
        hcluster tree with distance<dist."""
        if self.distance < dist:
            return [self]
        return self.left.extract_clusters(dist) + self.right.extract_clusters(dist)
    
    def get_cluster_elements(self):
        """ Return ids for elements in a cluster sub-tree. """
        return self.left.get_cluster_elements() + self.right.get_cluster_elements()
    
    def get_height(self):
        """ Return the height of a node,
        height ios sum of each branch. """
        return self.left.get_height() + self.right.get_height()
    
    def get_depth(self):
        """ Return the depth of a node,
        node is max of each child plus own distance. """
        return max(self.left.get_depth(), self.right.get_depth()) + self.distance
    
    def draw(self, draw, x, y, s, tags, im):
            """ Draw nodes recursively with image
            thumbnails for leaf nodes. """
            h1 = int(self.left.get_height()*20 / 2)
            h2 = int(self.right.get_height()*20 / 2)
            top = y-(h1+h2)
            bottom = y+(h1+h2)
            #vertical line to children
            draw.line((x,top+h1,x,bottom-h2),fill=(0,0,0))
            #horizontal lines
            ll = self.distance*s
            draw.line((x,top+h1,x+ll,top+h1),fill=(0,0,0))
            draw.line((x,bottom-h2,x+ll,bottom-h2),fill=(0,0,0))
            #draw left and right child nodes recursively
            self.left.draw(draw,x+ll,top+h1,s,tags,im)
            self.right.draw(draw,x+ll,bottom-h2,s,tags,im)    
    
class ClusterLeafNode(object):
    def __init__(self, vec, id, label=None):
        self.vec = array(vec)
        self.id = id
        self.label = label
        
    def extract_clusters(self, dist):
        return [self]
    
    def get_cluster_elements(self):
        return [self.id]
    
    def get_height(self):
        return 1
    
    def get_depth(self):
        return 0
    
    def draw(self,draw,x,y,s,tags,im, pad=10,fontsize=10):
        font = ImageFont.truetype("/usr/share/fonts/truetype/ttf-dejavu/DejaVuSans.ttf", fontsize)
        tagText = str(tags)
        tagColor = (0,0,150)
        draw.line((int(x),y,x+pad,y), fill=(0,0,0))
        draw.text((x+pad+fontsize//2,y-fontsize//2), tagText, font=font, fill=tagColor)
    
    
def L2dist(v1, v2):
    return sqrt(sum((v1 - v2)**2))

def L1dist(v1, v2):
    return sum(abs(v1 - v2))

def hcluster(features, distfcn=L2dist):
    """ Cluster the rows of features using hierarchical clustering """
    #cache of distance calculations
    distances = {}
    #initialize with each row as a cluster
    node = [ClusterLeafNode(f, i) for i,f in enumerate(features)]
    while len(node) > 1:
        closest = float('Inf')
        #loop through every pair looking for the smallest distance
        for ni, nj in combinations(node, 2):
            if (ni, nj) not in distances:
                distances[ni, nj] = distfcn(ni.vec, nj.vec)
            d = distances[ni, nj]
            if d < closest:
                closest = d
                lowestpair = (ni, nj)
        ni, nj = lowestpair
        #average the two clusters
        new_vec = (ni.vec + nj.vec) /2.0
        #create new node
        new_node = ClusterNode(new_vec, left=ni, right=nj, distance=closest)
        node.remove(ni)
        node.remove(nj)
        node.append(new_node)
    return node[0]

def draw_dendrogram(node, tags, filename='clusters.jpg'):
    """ Draw a cluster dendrogram and save toa file. """
    #height and width
    rows = node.get_height()*20
    cols = 1000
    #scale factor for distances to fit image width
    s = float(cols-150)/node.get_depth()
    #create image and draw object
    im = Image.new('RGB', (cols,rows),(255,255,255))
    draw = ImageDraw.Draw(im)
    #Initial line for start of tree
    draw.line((0,rows/2,20,rows/2),fill=(0,0,0))
    #draw the nodes recursively
    node.draw(draw,20,(rows/2),s,tags,im)
    im.save(filename)
    im.show()
                
            