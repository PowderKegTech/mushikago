const timer = {
  namespaced: true,
  state: {
    result: undefined
  },
  mutations: {
    setResult(state, data) {
      state.result = data
    },
    clearResult(state) {
      state.result = undefined
    }
  },
  actions: {
    setResult({ commit }, data) {
      commit("setResult", data)
    },
    clearResult({ commit }) {
      commit("clearResult")
    }
  }
};

export default timer;
