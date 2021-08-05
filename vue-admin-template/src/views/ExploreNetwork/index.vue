<template>
	<div id = 'forcedata'>
	</div>
</template>

<script>
import * as d3 from 'd3'

export default {
	 data() {
     	  return {
 	     graph: []
     	  }
  	 },
  	 mounted() {
    		this.create()
  	 },
  	 methods: {
    		create() {
     	 	var margin = { top: 30, bottom: 60, right: 30, left: 60 }
      		const width = 1600 - margin.left - margin.right
     	        const height = 1400 - margin.top - margin.bottom
		var svg = d3.select('#forcedata').append('svg')
	                    .attr('width', width)
                            .attr('height', height)
                            .attr('cursor', 'grab')
                            .attr('position', 'relative')
		var color = d3.scaleOrdinal().range(d3.schemeSet2);
		var simulation = d3.forceSimulation()
       			       	.velocityDecay(0.4)                         //摩擦
    				.force('charge', d3.forceManyBody())        //詳細設定は後で
   				.force('link', d3.forceLink().id(function(d) { return d.id; }))    //詳細設定は後で
			        .force('colllision',d3.forceCollide(40))    //nodeの衝突半径：Nodeの最大値と同じ
      				.force('positioningX',d3.forceX())                      //詳細設定は後で
 				.force('positioningY',d3.forceY())                      //詳細設定は後で
 				.force('center', d3.forceCenter(width / 2, height / 2));     //重力の中心

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

      		d3.json('nodes.json')
       		  .then(function(graph) { 
		  var link = g.append("g")  //svg⇒gに
		      .attr("class", "links")
		    .selectAll("line")
		    .data(graph.links)
		    .enter().append("line")
		      .attr("stroke","#999")  //輪郭線の色指定追加
		      .attr("stroke-width", function(d) { return Math.sqrt(d.value); })
		      .call(d3.drag()　              //無いとエラーになる。。
			  .on('start', dragstarted)
			  .on('drag', dragged)
			  .on('end', dragended));

		 // nodeの定義
		  var node = g.append('g')
		      .attr('class', 'nodes')
		    .selectAll('g')
		    .data(graph.nodes)
		    .enter()
		    .append('g')
		    .call(d3.drag()
			.on('start', dragstarted)
			.on('drag', dragged)
			.on('end', dragended));

		 // node circleの定義
		  node.append('circle')
		    .attr('r', 20)   //5⇒20
		    .attr('stroke', '#ccc')
		    .attr('fill', function(d) { return color(d.group); })
		    .style('stroke-width', '2');  //線の太さ

		 //node textの定義
		  node.append('text')
		    .attr('text-anchor', 'middle')
		    .attr('fill', 'black')
		    .style('pointer-events', 'none')
		    .attr('font-size', function(d) {return '10px'; }  )
		    .attr('font-weight', function(d) { return 'bold'; }  )
		    .text(function(d) { return d.id; });


	         /*	 //node.append("title")
		  //   .text(function(d) { return d.id; });
		 node.append("use")
		    .attr("xlink:href",function(d) {return "#"+ nodeTypeID(d.group)})        //図形判定
		    .attr('stroke', '#ccc')
		    .attr('fill', function(d) { return color(d.group); })
		    .style('stroke-width', '2')  //線の太さ
		    .style('stroke-dasharray',function(d) {return stroke_dasharrayCD(d)})  //破線判定
		    .on('mouseover', function(event,d){
			  d3.select(this).attr('fill', 'red'); //カーソルが合ったら赤に
			  datatip.style("left", event.pageX + 20 + "px")
				  .style("top", event.pageY + 20 + "px")
				  .style("z-index", 0)
				  .style("opacity", 1)
				  .style("z-index", 0)
				  //.style('background-image', )function() {if (typeof d.image === "undefined" ) {return  'url("image/unknown.png")' } else { return 'url("'+ d.image + '")'}})


                          console.log('HELLO')
			  datatip.select("h2")
				  .style("border-bottom", "2px solid " +color(d.group))
				  .style("margin-right", "0px")
				  .text(d.id);

			  datatip.select("p")
				  .text("グループID:" + d.group );
		      })
		    .on('mousemove', function(event){
			  datatip.style("left", event.pageX + 20 + "px")
				  .style("top", event.pageY + 20 + "px")
		      })
		    .on('mouseout', function(){
			  d3.select(this).attr('fill', function(d) { return color(d.group); })  //カーソルが外れたら元の色に
			  datatip.style("z-index", -1)
				 .style("opacity", 0)
		      })*/


		  simulation
		      .nodes(graph.nodes)
		      .on("tick", ticked);

		  simulation.force("link")
		      .distance(100) //Link長
		      .links(graph.links);

		  simulation.force('charge')
		      .strength(function(d) {return -300})  //node間の力

		  simulation.force('positioningX')        //X方向の中心に向けた引力
		      .strength(0.04)

		  simulation.force('positioningY')        //Y方向の中心に向けた引力
		      .strength(0.04)


		  function ticked() {
		    link
			.attr("x1", function(d) { return d.source.x; })
			.attr("y1", function(d) { return d.source.y; })
			.attr("x2", function(d) { return d.target.x; })
			.attr("y2", function(d) { return d.target.y; });

		    node
			.attr("cx", function(d) { return d.x; })
			.attr("cy", function(d) { return d.y; })
			.attr('transform', function(d) {return 'translate(' + d.x + ',' + d.y + ')'}) 
			  //nodesの要素が連動して動くように設定
		  }
		 })

		 function dragstarted(event,d) {
		  if (!event.active) simulation.alphaTarget(0.3).restart();
		  d.fx = d.x;
		  d.fy = d.y;
		 }

		 function dragged(event,d) {
		  d.fx = event.x;
		  d.fy = event.y;
		 }

		 function dragended(event,d) {
		  if (!event.active) simulation.alphaTarget(0);
		  d.fx = null;
		  d.fy = null;
		 }
            
		 //図形判定
                 function nodeTypeID(d){
                 var nodetype
                 var arrRect = [3,4]
                 var arrEllipse = [5,6,7]
                 var arrHexagon = [9,10,11,12,0]
                
                 if(arrRect.indexOf(d) >= 0){
                   //Rect
                   return "rect"
                 }
                 else if(arrEllipse.indexOf(d) >= 0){
                   //Ellipse
                   return "ellipse"
                 }
                 else if(arrHexagon.indexOf(d) >= 0){
                   //Hexagon
                   return "hexagon"
                 }
                 else{
                   //Circle
                   return "circle"
                 }
                }

                 //破線判定
                 function stroke_dasharrayCD(d){
                 var arr = [2,4,6,7,9,10,11,12,0]
                 if (arr.indexOf(d.group) >= 0) {
                   return "3 2"  //3:2の破線
                 }
                 else {
                   return "none"  //破線なし
                 }
                }
	      }
        }
}
</script>
