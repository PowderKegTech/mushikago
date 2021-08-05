import * as MutationTypes from './mutationTypes'

export const state = {
  elapsedTime: 0,
  active: false,
  itmode: false,
  otmode: false,
  intervalToken: null
}

export const mutations = {
  [MutationTypes.TICK] (state) {
    state.elapsedTime += 1
  },

  [MutationTypes.START] (state, intervalToken) {
    state.active = true
    state.intervalToken = intervalToken
  },

  [MutationTypes.STOP] (state) {
    clearInterval(state.intervalToken)

    state.intervalToken = null
    state.active = false
  },

  [MutationTypes.RESET] (state) {
    state.elapsedTime = 0
  },
  
  [MutationTypes.ITMODE] (state) {
    state.itmode = true
    state.otmode = false
  },
  
  [MutationTypes.OTMODE] (state) {
    state.itmode = false
    state.otmode = true
  }
}
