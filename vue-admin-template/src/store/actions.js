import * as MutationTypes from './mutationTypes'
export const start = ({ commit, state }) => {
  var interval = setInterval(() => {
    if (state.elapsedTime > -1) {
      commit(MutationTypes.TICK)
    } else {
      commit(MutationTypes.TICK)
    }
  }, 100)

  commit(MutationTypes.START, interval)
}

export const stop = ({ commit }) => commit(MutationTypes.STOP)

export const reset = ({ commit }) => commit(MutationTypes.RESET)

export const itmode = ({ commit }) => commit(MutationTypes.ITMODE)

export const otmode = ({ commit }) => commit(MutationTypes.OTMODE)
