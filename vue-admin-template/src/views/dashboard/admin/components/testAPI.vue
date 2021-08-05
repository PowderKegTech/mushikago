<template>

  <div>
    <h1>デモ画面</h1>
    <input type="button" value="移動" @click="goNewTask()"> <br>
    <input type="number" v-model="message"><input type="button" value="取得" @click="getdata()">
    <p> <font size="2"> 入力データ :{{ $data.message }} </font> </p>
    <p> <font size="2"> 出力データ :{{ $data.result }} </font> </p>
    <p> <font size="2"> 状態 :{{ $data.state }} </font> </p>
  </div>

</template>

<script>
// eslint-disable-next-line
/* eslint-disable */ 
import * as d3 from 'd3'  //有効にする

export default {
  name: 'sample',
  data: function(){
    return { 
        message:'',  //入力データを格納する変数。
        result :'',  //演算結果を格納する変数。
        state:"wait" //現在の状況を格納する変数。
    }
  },
  methods: {
    //テキストボックスに入力されたデータをバックエンドに送り、バックエンドから演算結果を受け取り、その結果を表示するメソッド
    getdata:function(){
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
            }.bind(this))}

  } 
}

</script>

