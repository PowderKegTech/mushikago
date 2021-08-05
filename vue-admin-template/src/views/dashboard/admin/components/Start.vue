<template>
  <div id="timer">
     <h1 v-if="itmode">Running in IT Pen Testing: {{ parseInt(elapsedTime/36000) }}:{{ parseInt(elapsedTime/600)%60 }}:{{ parseInt(elapsedTime/10)%60 }}:{{ elapsedTime%10 }}</h1>
     <h1 v-if="otmode">Running in OT Pen Testing: {{ parseInt(elapsedTime/36000) }}:{{ parseInt(elapsedTime/600)%60 }}:{{ parseInt(elapsedTime/10)%60 }}:{{ elapsedTime%10 }}</h1>
    <button v-on:click="start(); itstart()" v-bind:disabled="active">Start IT Pentesting</button>
    <button v-on:click="start(); otstart()" v-bind:disabled="active">Start OT Pentesting</button>
    <button v-on:click="stop" v-bind:disabled="!active">Stop</button>
    <button v-on:click="reset" v-bind:disabled="active">Reset</button>
    <img v-if="active" src ='./run.gif'></img>
  </div>
</template>

<script>
import { mapActions } from 'vuex'
export default {
  computed: {
    elapsedTime () {
      return this.$store.state.elapsedTime
    },
    active () {
      return this.$store.state.active
    },
    itmode () {
      return this.$store.state.itmode
    },
    otmode () {
      return this.$store.state.otmode
    }
  },
  methods: {
    start: function() {
      this.$store.dispatch('start')
        },
    stop: function () {
      this.$store.dispatch('stop')
        },
    reset: function () {
      this.$store.dispatch('reset')
        },
    itstart: function () {
      this.$store.dispatch('itmode')
      this.state="getting data"
      this.$axios.get('http://192.168.11.6:3000/api').then(function(response){
          console.log(response)  //Logging the calculation results returned from the backend in console.log
          this.state="done"    
          }.bind(this))  //Promise processing requires .bind(this)
        .catch(function(error){  //What to do when an error is returned from the backend
          this.state="ERROR"
          }.bind(this))
        .finally(function(){
          }.bind(this))
        },
    otstart: function () {
      this.$store.dispatch('otmode')
      let self = this;
      this.state="getting data"
      this.$axios.get('http://192.168.11.6:4000/api').then(function(response){
          console.log(response)  //Logging the calculation results returned from the backend in console.lou
          this.state="done"    
          }.bind(this))  //Promise processing requires .bind(this)
        .catch(function(error){  //What to do when an error is returned from the backend
          this.state="ERROR"
          }.bind(this))
        .finally(function(){
          }.bind(this))
    }
 }
}
</script>

<style>
html {
  height: 100%;
}
body {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;
}
#timer {
  color: #2c3e50;
  margin-top: -100px;
  max-width: 600px;
  font-family: Source Sans Pro, Helvetica, sans-serif;
  text-align: center;
}
</style>
