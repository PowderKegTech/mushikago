import Vue from 'vue'
import Vuex from 'vuex'
import getters from './getters'
import app from './modules/app'
import settings from './modules/settings'
import user from './modules/user'
import { state, mutations } from './mutations'
import * as actions from './actions'


Vue.use(Vuex)

const store = new Vuex.Store({
  modules: {
    app,
    settings,
    user
  },
  actions,
  state,
  mutations,
  getters
})

export default store
