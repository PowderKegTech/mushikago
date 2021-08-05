<template>
  <div id="timer">
    <div class="timer">
      <div class="time">
        {{ formatTime }}
      </div>
      <h1 v-if="modeIT">Running in IT Pen Testing</h1>
      <h2 v-if="modeOT">Running in OT Pen Testing</h2>
      <button v-on:click="start" v-if="!timerOn">Start IT Pen Testing</button>
      <button v-on:click="start2" v-if="!timerOn">Start OT Pen Testing</button>
      <button v-on:click="stop" v-if="timerOn">Stop</button>
      </div>
     <img v-if="timerOn" src ='./run.gif'>
     <img v-if="!timerOn" src ='./stop.jpg' width=250 height=250>
  </div>
</template>

<script>
import { mapActions } from 'vuex'
export default {
  name: 'timer',
  data() {
    return {
      min: 348,
      sec: 27,
      timerOn: false,
      timerObj: null,
      modeIT: false,
      modeOT: false
    }
  },
  methods: {
    count: function() {
      if (this.sec == 59 ) {
        this.min ++;
        this.sec = 0;
      } else {
        this.sec ++;
      }
    },

    start: function() {
      let self = this;
      this.timerObj = setInterval(function() {self.count()}, 1000)
      this.timerOn = true; //timerがONであることを状態として保持
      this.modeIT = true; //timerがONであることを状態として保持
      this.state="getting data"
      this.$axios.get('http://192.168.11.6:3000/api',{params:{data:this.message}})
        .then(function(response){
          console.log(response.data.message)  //バックエンドから返却された演算結果をconsole.logしている。
          this.result= response.data.message
          this.state="done"    
          }.bind(this))  //Promise処理を行う場合は.bind(this)が必要
        .catch(function(error){  //バックエンドからエラーが返却された場合に行う処理について
          this.state="ERROR"
          }.bind(this))
        .finally(function(){
          }.bind(this))
    },
    start2: function() {
      let self = this;
      this.timerObj = setInterval(function() {self.count()}, 1000)
      this.timerOn = true; //timerがONであることを状態として保持
      this.modeOT = true; //timerがONであることを状態として保持
      this.state="getting data"
      this.$axios.get('http://192.168.11.6:4000/api',{params:{data:this.message}})
        .then(function(response){
          console.log(response.data.message)  //バックエンドから返却された演算結果をconsole.logしている。
          this.result= response.data.message
          this.state="done"    
          }.bind(this))  //Promise処理を行う場合は.bind(this)が必要
        .catch(function(error){  //バックエンドからエラーが返却された場合に行う処理について
          this.state="ERROR"
          }.bind(this))
        .finally(function(){
          }.bind(this))
    },

    stop: function() {
      clearInterval(this.timerObj);
      this.timerOn = false; //timerがOFFであることを状態として保持
      this.modeIT = false;
      this.modeOT = false;
    },

    complete: function() {
      clearInterval(this.timerObj)
    }
  },
  computed: {
    formatTime: function() {
      let timeStrings = [
        this.min.toString(),
        this.sec.toString()
      ].map(function(str) {
        if (str.length < 2) {
          return "0" + str
        } else {
          return str
        }
      })
      return timeStrings[0] + ":" + timeStrings[1]
    }
  }
}
</script>

<style scoped>
#timer {
  background: #FFFF;
  display: flex;
  align-items: center;
  justify-content: center;
}
.time {
  font-size: 100px;
}
</style>
