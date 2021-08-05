<template>
  <div id="processtree"/>
</template>

<script>
import * as d3 from 'd3'

export default {
  data() {
    return {
      treeData: []
    }
  },
  mounted() {
    this.create()
  },
  methods: {
    create() {
      var margin = { top: 60, right: 270, bottom: 90, left: 270 }
      const width = 4000 - margin.left - margin.right
      const height = 2000 - margin.top - margin.bottom
      // declares a tree layout and assigns the size
      var treemap = d3.tree()
        .size([height, width])
      // load the external data
      d3.csv('attack_tree.csv')
        .then(function(csvData) { //.then(function(treeData)
        var treeData = d3.stratify()
             .id(function(d) { return d.name; })
             .parentId(function(d) { return d.parent; })(csvData)
	    treeData.each(function(d) {
             d.name = d.id;
	    })
	var nodes = d3.hierarchy(treeData, function(d) {
          return d.children
        })

        // maps the node data to the tree layout
        nodes = treemap(nodes)

        // append the svg object to the body of the page
        // appends a 'group' element to 'svg'
        // moves the 'group' element to the top left margin
        var svg = d3
           .select('#processtree')
           .append('svg')
           .attr('width', width + margin.left + margin.right)
           .attr('height', height + margin.top + margin.bottom)
           .attr('cursor', 'grab')
           .attr('position', 'relative')
        var g = svg.append('g')
           .attr('transform', 'translate(' + margin.left + ', ' + margin.top + ')')
     //"svg"にZoomイベントを設定
      var zoom = d3.zoom()
        .scaleExtent([1/4,4])
        .on('zoom', SVGzoomed);
 
      svg.call(zoom);
 
      //"svg"上に"g"をappendしてdragイベントを設定
      var g = svg.append("g")
        .call(d3.drag()
        .on('drag',SVGdragged))
 
      function SVGzoomed(event) {
        g.attr("transform", event.transform);
      }
       function SVGdragged(event,d) {
     d3.select(this).attr('cx', d.x = event.x).attr('cy', d.y = event.y);
        };

  // adds the links between the nodes
  var link = g.selectAll('.link')
    .data(nodes.descendants().slice(1))
    .enter().append('path')
    .attr('class', 'link')
    .attr('d', function(d) {
       return 'M' + d.y + ',' + d.x + 'C' + (d.y + d.parent.y) / 2 + ',' + d.x + ' ' + (d.y + d.parent.y) / 2 + ',' + d.parent.x + ' ' + d.parent.y + ',' + d.parent.x
       })

  // adds each node as a group
  var node = g.selectAll('.node')
    .data(nodes.descendants())
    .enter().append('g')
    .attr('class', function(d) {
      return 'node' + (d.children ? ' node--internal' : ' node--leaf')
    })
    .attr('transform', function(d) {
      return 'translate(' + d.y + ',' + d.x + ')'
    })

  // adds the circle to the node
  node.append('circle')
    .attr('r', 10)

  // adds the text to the node
  node.append('text')
    .attr('dy', '.35em')
    .attr('x', function(d) { return d.children ? -13 : 13 })
    .style('text-anchor', function(d) {
    return d.children ? 'end' : 'start'
    })
    .text(function(d) { return d.data.name })
   })
  }
 }
}
    
</script>

<style>

.node circle {
  fill: #fff;
  stroke: steelblue;
  stroke-width: 3px;
}

.node text { font: 12px sans-serif; }

.node--internal text {
  text-shadow: 0 1px 0 #fff, 0 -1px 0 #fff, 1px 0 0 #fff, -1px 0 0 #fff;
}

.link {
  fill: none;
  stroke: #ccc;
  stroke-width: 2px;
}

</style>
